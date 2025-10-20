import os
import psycopg2  # PostgreSQL
import secrets
import time
import bcrypt
from flask import Flask, jsonify, request
from functools import wraps
from dotenv import load_dotenv  # Для загрузки переменных окружения из .env файла

# Если приложение запущено локально, а не в Railway — загружаем переменные из .env
if os.environ.get("RAILWAY_ENVIRONMENT") is None:
    load_dotenv()

app = Flask(__name__)


bDebug = True



# ==============================================================
# --------------------------------------------------------------
# 🔐 Звичайна база користувачів та токенів

# USERS = {"admin": "1234"}
# TOKENS = {}  # token -> (username, expiry)
TOKEN_TTL = 172800  # 48 годин
# TOKENS["tokenstring"] = [user_id, user_login, user_name, token_expire_date]
TOKENS = {}


# ==============================================================
# --------------------------------------------------------------
# 💾 Функція підключення до БД, викликається з кожного маршруту, де потрібно звертатися до бази

def get_db_connection():
    db_url = os.getenv("DATABASE_URL")  # Читаем URL базы из переменной окружения
    if not db_url:
        raise RuntimeError("DATABASE_URL не задана.")
    return psycopg2.connect(db_url)


# ==============================================================
# --------------------------------------------------------------
# 🔐 Декоратор авторизації

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({"error": "Authorization header missing"}), 401

        token = auth.split(' ')[1]
        # user_data = TOKENS.get(token)
        if token in TOKENS:
            user_data = TOKENS[token]
        else:
            return jsonify({"error": "Invalid or expired token"}), 401

        # if not user_data:
        #    return jsonify({"error": "Invalid or expired token"}), 401

        # username, expiry = user_data
        user_id, user_login, user_name, token_expire_date = user_data

        if time.time() > token_expire_date:
            del TOKENS[token]
            return jsonify({"error": "Token expired"}), 401

        request.user_id = user_id
        request.user_login = user_login
        request.user_name = user_name

        return f(*args, **kwargs)

    return decorated


# --------------------------------------------------------------
# 🔐 Точка входу для отримання токену
@app.route('/login', methods=['POST'])
def login():

    bDebug = True

    if bDebug:
        print('+++ Login')

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    if bDebug:
        print('    username:' + str(username) + '; password:' + str(password))

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        sql = """
            select usr.id, usr.login, usr.first_name, usr.last_name, usr.phone
            from customers usr
            where 	usr.enabled = true 
                and usr.login = %s 
                and usr.phrase = %s"""

        params = [username, password]
        cur.execute(sql, params)
        row = cur.fetchone()
        rows_count = cur.rowcount

        if bDebug:
            print('    data fetched: ', row)

        if rows_count == 1:
            token = secrets.token_hex(16)
            TOKENS[token] = [row[0], row[1], row[2] + " " + row[3], time.time() + TOKEN_TTL]
            cur.close()
            conn.close()
            if bDebug:
                print('    TOKEN Result: ', TOKENS[token])
            return jsonify(
                {
                    "token" : token,
                    "user"  : row[2] + " " + row[3],
                    "phone" : row[4]
                })

        else:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        #cur.close()
        #conn.close()
        return jsonify({"error": str(e)}), 500  # Ошибка сервера

    # if USERS.get(username) != password:
    #     return jsonify({"error": "Invalid credentials"}), 401

    # token = secrets.token_hex(16)
    # TOKENS[token] = (username, time.time() + TOKEN_TTL)

    # return jsonify({"token": token})


# ==============================================================
# --------------------------------------------------------------
@app.route("/languages")
@require_auth
def get_languages():

    print('+++/languages: user:'+str(request.user_id))

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT code, title FROM public.languages ORDER BY title;")
        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()

        datarows = [
            {"code": row[0].strip(), "title": row[1]}
            for row in rows
        ]

        data = {
            "count": rows_count,
            "languages": datarows
        }

        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================
# --------------------------------------------------------------
@app.route("/currencies")
@require_auth
def get_currencies():

    print('+++/currencies: user:' + str(request.user_id))

    lang = request.args.get('lang', 'ua')
    lang = lang.lower()
    if lang not in ['ua', 'pl', 'en', 'ru']:
        lang = 'ua'

    col_title = 'title_' + lang

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT code, " + col_title + " FROM public.currencies ORDER BY code;")

        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()

        datarows = [
            {"code": row[0].strip(), "title": row[1]}
            for row in rows
        ]

        data = {
            "count": rows_count,
            "currencies": datarows
        }

        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================
# --------------------------------------------------------------
# 📗 Запит товарних категорій
@app.route("/categories")
@require_auth
def get_categories():

    bDebug = True

    if bDebug:
        print('+++ Get Categories: user:' + str(request.user_id))

    lang = request.args.get('lang', 'ua')
    lang = lang.lower()
    if lang not in ['ua', 'pl', 'en', 'ru']:
        lang = 'ua'

    col_title = 'title_' + lang

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT 
            	c.id, 
            	c.code, 
            	c.""" + col_title + """, 
            	COUNT(p.id) as ProductCount
            FROM 
                Categories c
            LEFT JOIN 
                Products p ON c.code = p.category_code
            GROUP BY 
                c.id, c."""+col_title+""" 
            ORDER BY c.code;""")

        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()

        if bDebug:
            print('    data fetched: ' + str(rows_count) + ' rows')

        datarows = [
            {"id": row[0], "code": row[1].strip(), "title": row[2], "prod_count": row[3]}
            for row in rows
        ]

        data = {
            "count": rows_count,
            "categories": datarows
        }

        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================
# --------------------------------------------------------------
# 📦 Отримати список товарів [GET]
#    Отримати перелік товарів.
#    Також, для кожної категоріі повертається кількість підпорядковиних товарів.
# Когда ты стучишься к аппке GET-запросом по адресу https://<аппка>/products
# то вызывается функция, которая описана непосредственно под определением роута "@app.route('/products', methods=['GET'])"
# В нашем случае - get_products()
# Так во фласке построена вся маршрутизация
@app.route('/products', methods=['GET'])
@require_auth
def get_products():

    if bDebug:
        print('+++/products: user:' + str(request.user_id))

    # Получаем параметры запроса
    # это именно GET-параметры - request.args.get(param name)
    # как работать с POST описал в комментах в create_order()

    req_start = request.args.get('start')
    req_limit = request.args.get('limit')

    req_category = request.args.get('category')
    # category_type = type(req_category)

    req_currency = request.args.get('currency', 'uah')
    req_currency = req_currency.lower()
    if req_currency == '':
        req_currency = 'uah'

    req_lang = request.args.get('lang', 'ua')
    req_lang = req_lang.lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'

    if req_start is None:
        req_start = 0

    if req_limit is None:
        req_limit = 40

    if bDebug:
        print('    start:'+str(req_start)+ '; limit:'+str(req_limit))
        print('    category:' + str(req_category) + '; currency:' + req_currency + '; lang:' + req_lang)

    col_title = 'title_' + req_lang

    try:
        # Запрос к БД
        conn = get_db_connection()
        cur = conn.cursor()

        sql = """
            SELECT 
                p.id AS product_id,
                c.code AS category_name,
                p.""" + col_title + """ AS product_title,
                pl.price,
                pl.stock_quantity
            FROM products p
            LEFT JOIN categories c ON p.category_code = c.code
            LEFT JOIN price_list pl ON p.code = pl.product_code  AND pl.currency_code = %s
            """

        # Это параметризирванные запросы, защита от инъекций в SQL
        # В тексте SQL ставишь параметры типа %s и кодом "params = [currency, lang]" запихиваешь их в список
        # params = [currency, lang]
        params = [req_currency]

        if req_category:
            # И добавляешь в список параметров SQL-запроса
            params.append(req_category)

            if isinstance(req_category, str) == True:
                sql += "    WHERE c.code = %s"
            else:
                sql += "    WHERE c.id = %s"

        sql += """
            ORDER BY c.code, p.""" + col_title

        if req_limit <= 0:
            req_limit = 40
        sql += "    LIMIT " + str(req_limit)

        if req_start > 0:
            sql += "    OFFSET " + str(req_start)

        # При выполнении запроса либа проверит и подставит твои параметры запроса

        if bDebug:
            print('    sql :')
            print('' + sql)
            print('  ')
            print('    params :')
            print('' + str(params))

        cur.execute(sql, params)
        rows = cur.fetchall()
        rows_count = cur.rowcount

        # Запихиваем результаты запроса в выходной массив
        products = []
        for row in rows:
            products.append({
                'id': row[0],
                'category': row[1],
                'title': row[2],
                'description': '',
                'image': '',
                'measure': '',
                'quantity': row[4],
                'price': float(row[3])
            })

        # Дисконнект к БД
        cur.close()
        conn.close()

        data = {
            "currency": req_currency,
            "count": rows_count,
            "start": req_start,
            "limit": req_limit,
            "products": products
        }

        # Из массивов python делает массив JSON
        # Если тебе нужно отдать ответ в виде {...}, то перед jsonify() можешь запихать его в структуру типа
        # response = {
        #     "result": "ok",
        #     "products": products
        # }
        # return jsonify(response), 200

        if products:
            return jsonify(data), 200

        return jsonify({"message": "No products found"})


    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Ошибка сервера


# --------------------------------------------------------------
# 📦 Запит конкретного товару
@app.route('/products/<int:product_id>', methods=['GET'])
@require_auth
def get_product(product_id):
    # перевірка на заповненність АйДи товару
    # product_id = request.args.get('product_id', 0)
    if product_id == 0:
        return jsonify({"message": "No product ID specified"}), 400

    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah')
    req_currency = req_currency.lower()
    if req_currency == '':
        req_currency = 'uah'

    # бажана мова, або Українська
    req_lang = request.args.get('lang', 'ua')
    req_lang = req_lang.lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'
    # відповідна назва колонок
    col_title = 'title_' + req_lang
    col_descr = 'descr_' + req_lang

    # 1
    # отримаємо данні про товар
    try:
        # Запит до БД
        conn = get_db_connection()
        cur = conn.cursor()
        sql = """
            select 
                p.id,
                p.category_id,
                c.code AS category,
                p.is_active as active,
                p.""" + col_title + """ as title,
                p.""" + col_descr + """ as description,
                p.updated_at,
                pl.price,
                pl.stock_quantity,
                i.img_data
            from Products p
            inner join categories c ON p.category_id = c.id
            inner join price_list pl ON pl.product_id = p.id AND pl.currency_code = '""" + req_currency + """'
            left join images i ON i.product_id = p.id
            where p.id = %s"""

        cur.execute(sql, (product_id,))
        rows = cur.fetchall()
        rows_count = cur.rowcount

        # Дисконнект від БД
        cur.close()
        conn.close()

    except Exception as e:
        return jsonify({"error (1): ": str(e)}), 500  # Ошибка сервера

    # має бути лише один!
    if rows_count == 0:
        return jsonify({"no records found"}), 500  # Ошибка сервера

    if rows_count != 1:
        return jsonify({"records more than expected"}), 500  # Ошибка сервера

    # 2
    # отримаємо зображення товару
    try:
        # Запит до БД
        conn = get_db_connection()
        cur = conn.cursor()
        sql = """
            select 
                i.img_data 
            from images i
            where i.product_id = %s
            order by i.id"""

        cur.execute(sql, (product_id,))
        img_rows = cur.fetchall()
        # img_count = cur.rowcount

        # Дисконнект від БД
        cur.close()
        conn.close()

    except Exception as e:
        return jsonify({"error (2): ": str(e)}), 500  # Ошибка сервера

    try:

        # Заносимо зображення у масив
        images = []
        for row in img_rows:
            images.append({'image': row[0]})

        # Заносимо данні
        first_row = rows[0]
        data = {
            "id": first_row[0],
            "category_id": first_row[1],
            "category": first_row[2],
            "active": first_row[3],
            "title": first_row[4],
            "description": first_row[5],
            "image": first_row[9],
            "quantity": first_row[8],
            "price": first_row[7],
            "images": images
        }

        return jsonify(data), 200


    except Exception as e:
        return jsonify({"error (3): ": str(e)}), 500  # Ошибка сервера


# ==============================================================
# --------------------------------------------------------------
# 🛒 Запит кошика
@app.route("/cart")
@require_auth
def get_cart():
    # print('request.user_id : ', request.user_id)

    # бажана мова, або Українська
    req_lang = request.args.get('lang', 'ua')
    req_lang = req_lang.lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'

    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah')
    req_currency = req_currency.lower()
    if req_currency == '':
        req_currency = 'uah'

    # відповідна назва колонок
    col_title = 'title_' + req_lang
    col_descr = 'descr_' + req_lang

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # cur.execute("SELECT id, code, " + col_title + " FROM public.categories ORDER BY id;")

        sql = """
            select 
                c.id,
                c.customer_id,
                c.product_id,
                pr.category_id,
                cat.code,
                pr.""" + col_title + """ as title,
                pr.""" + col_descr + """ as description,
                i.img_data,
                c.quantity,
                pl.price,
                c.quantity * pl.price as summ 
            from carts c 
            inner join products pr ON pr.id = c.product_id
            inner join price_list pl ON pl.product_id = c.product_id AND pl.currency_code = '""" + req_currency + """'
            inner join categories cat ON cat.id = pr.category_id
            left join images i ON i.product_id = c.product_id
            where c.customer_id = """ + str(request.user_id)

        cur.execute(sql)

        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()

        # Приклад структури що повертаємо:
        # {
        #     "count"   : 1,
        #     "total"   : 2.5,
        #     "products": [
        #         {
        #             "id"          : 719,
        #             "category"    : "cat_profile",
        #             "title"       : "Профіль для 2-х рівневої стелі під 45° 2,5 м",
        #             "image"       : "storage\images\719-1.jpg",
        #             "measure"     : "шт.",
        #             "quantity"    : 1,
        #             "price"       : 2.5
        #             "summ"        : 2.5

        #         }
        #     ]
        # }

        total_summ = 0
        productsdata = []

        for row in rows:
            productsdata.append(
                {"id": row[2],
                 "category": row[4],
                 "title": row[5],
                 "image": row[7],
                 "measure": "шт.",
                 "quantity": row[8],
                 "price": row[9],
                 "summ": row[10]
                 }
            )

            total_summ = total_summ + row[10]

        data = {
            "count": rows_count,
            "total": total_summ,
            "products": productsdata
        }

        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================
# --------------------------------------------------------------
@app.route('/orders', methods=['GET'])
@require_auth
def get_orders():
    # бажана мова, або Українська
    req_lang = request.args.get('lang', 'ua')
    req_lang = req_lang.lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'

    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah')
    req_currency = req_currency.lower()
    if req_currency == '':
        req_currency = 'uah'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Запрос с объединением заказов и их позиций
        cursor.execute("""
            SELECT 
                o.id,
                o.order_date,  
                o.invoice_date, 
                o.invoice_number,
                o.delivery_date, 
                o.total,
                o.status
            FROM orders o
            WHERE o.customer_id = """ + str(request.user_id) )

        orders = cursor.fetchall()

        orders_list = []

        for ordr in orders:
            orders_list.append(
                {   "id"            : ordr[0],
                    "TTN"           : ordr[3],
                    "date_ordered"  : ordr[1],
                    "date_delivered": ordr[4],
                    "status"        : ordr[6],
                    "summ"          : ordr[5]
                })

        cursor.close()
        conn.close()
        return jsonify(
            {   "count"     : len(orders_list),
                "orders"    : orders_list,  }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# ==============================================================
# --------------------------------------------------------------
@app.route('/orders/<int:order_id>', methods=['GET'])
@require_auth
def get_order(order_id):
    # перевірка на заповненність АйДи товару
    # order_id = request.args.get('order_id', 0)
    if order_id == 0:
        return jsonify({"message": "No product ID specified"}), 400

    # бажана мова, або Українська
    req_lang = request.args.get('lang', 'ua')
    req_lang = req_lang.lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'

    col_title = 'title_' + req_lang


    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah')
    req_currency = req_currency.lower()
    if req_currency == '':
        req_currency = 'uah'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Запрос с объединением заказов и их позиций
        cursor.execute("""
            SELECT 
                o.id, 
                o.customer_id, 
                o.invoice_date, 
                o.invoice_number, 
                o.total,
                o.status,
                oi.id as order_item_id, 
                oi.product_id, 
                oi.quantity, 
                oi.price,
                p.""" +col_title+ """ as product_name
            FROM orders o
            LEFT JOIN order_items oi ON o.id = oi.order_id
            LEFT JOIN products p ON p.id = oi.product_id 
            WHERE o.id = %s """, (order_id,))

        orders = cursor.fetchall()

        if orders:
            orders_list = []
            current_order_id = None
            for order in orders:

                order_id, customer_id, invoice_date, invoice_number, total, status, order_item_id, product_id, quantity, price, product_name = order

                if current_order_id != order_id:
                    # вже інший АйДі, отже інше замовлення.
                    if current_order_id is not None:
                        # якщо поточний АйДі не нульовий, додамо його до масиву результатів
                        orders_list.append(current_order_data)
                    # почнему накопичувати дані нового замовлення
                    current_order_data = {
                        "id": order_id,
                        "TTN": invoice_number,
                        "date_ordered": invoice_date,
                        "status": status,
                        "summ": total,
                        "items": []
                    }
                    current_order_id = order_id

                # додамо строку товара у замовлення
                current_order_data["items"].append({
                    "order_item_id": order_item_id,
                    "product_id": product_id,
                    "product_name": product_name,
                    "quantity": quantity,
                    "price": price
                })

            orders_list.append(current_order_data)
            cursor.close()
            conn.close()
            return jsonify(
                {
                    "count": len(orders_list),
                    "orders": orders_list,

                }), 200

        cursor.close()
        conn.close()
        return jsonify({"message": "No orders found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================
# --------------------------------------------------------------
@app.route('/orders/new', methods=['POST'])
@require_auth
def create_order():
    # Для POST-запроса параметры извлекаются немного по другому

    # 1. Если прилетело из веб-формы из стандартного сайта, типа
    # <form method="POST" action="/login">
    #   <input name="username">
    #   <input name="password">
    # </form>
    # то получаем их через методы типа username = request.form.get('username')

    # 2. Если в теле запроса прислали JSON, как это делают в REST-запросах (это наш случай), типа
    # Content-Type: application/json:
    # {
    #   "username": "Doe",
    #   "password": "secret"
    # }
    # , то используем data = request.get_json(), он отдает массив и обращается к нему дальше в коде
    # так - data['username']
    # или так - data.get('username')

    data = request.get_json()

    if not data     or 'products' not in data   or 'currency' not in data   or not request.user_id:
        return jsonify({"error": "Missing data"}), 400  # Проверка наличия данных

    currency = data['currency']
    products = data['products']

    if not products or not isinstance(products, list):
        return jsonify({"error": "products list is required"}), 400  # Проверка структуры

    #WHERE
    #o.customer_id = """ + str(request.user_id) )


    try:
        conn = get_db_connection()
        conn.autocommit = False     # manual transactions
        cursor = conn.cursor()

        try:
            # Вставляем заказ и получаем его ID
            cursor.execute(
                "INSERT INTO orders (customer_id, order_date, status, total) VALUES (%s, CURRENT_TIMESTAMP, 'new', 1) RETURNING id;",
                (str(request.user_id),)
            )
            order_id = cursor.fetchone()[0]
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        order_total = 0

        for item in products:

            product_id = item.get('id')
            quantity = item.get('quantity')
            # price       = item.get('price')
            try:
                cursor.execute("""
                SELECT 
                    p.id,
                    pl.price
                FROM Products p
                INNER join price_list pl ON pl.product_id = p.id AND pl.currency_code = '""" +currency+ """'
                WHERE p.id = %s""", (product_id,))

                results = cursor.fetchone()
            except Exception as e:
                return jsonify({"error": str(e)}), 500

            print('Product Results 0: ', results[0])
            price = results[1]
            print('Product Results 1: ', price)
            #price = cursor.fetchone()[1]
            total = price * quantity
            order_total = order_total + total

            if not all([product_id, quantity, price]):
                print('Пропускаем неполную строку')
                continue  # Пропускаем неполные строки

            try:
                cursor.execute(
                    "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (%s, %s, %s, %s);",
                    (order_id, product_id, quantity, price)
                )
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        cursor.execute("""
            UPDATE orders
            SET total = """ +str(order_total)+ """
            WHERE id = """ + str(order_id), ()
        )
        conn.commit()  # Сохраняем изменения
        cursor.close()
        conn.close()

        return jsonify({"message": "Order created successfully", "order_id": order_id}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================
# --------------------------------------------------------------
# Запуск приложения (локально или на хостинге)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))  # Слушаем все IP, порт по умолчанию — 5000

# Дополнительные файлы в проекте:

# Procfile
# Назначение: указывает, как запускать приложение на платформе вроде Railway, Heroku и др.
# Говорит системе развертывания: «Это веб-приложение, запускай его через python app.py».
# Ключевое слово web указывает, что это веб-сервис, который слушает HTTP-запросы.

# requirements.txt
# Назначение: список всех Python-зависимостей, нужных для запуска проекта.
# Командой pip install -r requirements.txt устанавливаются все библиотеки.
# Railway автоматически выполняет эту установку при развёртывании.

# .env
# Назначение: содержит секретные и конфигурационные переменные окружения, которые не должны попадать в публичный код.
# Используется библиотекой python-dotenv для подгрузки переменных в локальной среде.
# Позволяет удобно менять настройки (например, адрес БД) без правки кода.
# Важно: .env добавляют в .gitignore, чтобы не загрузить секреты в публичный репозиторий.
