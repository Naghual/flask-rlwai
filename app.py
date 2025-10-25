# flask-rlwai

import os
import psycopg2
import secrets
import time
import imghdr
import bcrypt
import base64
import logging
from flask import Flask, jsonify, request, send_from_directory
from psycopg2.extras import RealDictCursor
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from functools import wraps
from dotenv import load_dotenv  # Для загрузки переменных окружения из .env файла


# Если приложение запущено локально, а не в Railway — загружаем переменные из .env
if os.environ.get("RAILWAY_ENVIRONMENT") is None:
    load_dotenv()

app = Flask(__name__)

# Настройка логирования (замена print)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

bDebug = False
bDebug2= False

# Доступні значення для мов та валют
VALID_LANGS         = {'ua', 'pl', 'en', 'ru'}
VALID_CURRENCIES    = {'uah', 'pln', 'usd', 'eur'}
DEFAULT_LANG        = 'ua'
DEFAULT_CURRENCY    = 'uah'
DEFAULT_PAGE_LIMIT  = 50
MAX_PAGE_LIMIT      = 250



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

        request.user_id     = user_id
        request.user_login  = user_login
        request.user_name   = user_name

        return f(*args, **kwargs)

    return decorated


# --------------------------------------------------------------
# 🔐 Точка входу для отримання токену
@app.route('/login', methods=['POST'])
def login():

    if bDebug:
        print('+++ Login')

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get('username', '').lower()
    password = data.get('password', '').lower()

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    if bDebug2:
        print(f'    username: {username}; password: {password}')

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        sql = """
            select usr.id, usr.login, usr.first_name, usr.last_name, usr.phone
            from customers usr
            where   usr.enabled = true 
                and usr.login = %s 
                and usr.phrase = %s"""

        params = [username, password]
        cur.execute(sql, params)
        row = cur.fetchone()
        rows_count = cur.rowcount

        if bDebug2:
            print(f'    data fetched: {row}')

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

    print(f'+++/languages: user: {str(request.user_id)}')

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

    print(f'+++/currencies: user: {str(request.user_id)}')

    lang = request.args.get('lang', 'ua').lower()
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
        print(f'+++ Get Categories: user: {str(request.user_id)}')

    lang = request.args.get('lang', 'ua').lower()
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

        if bDebug2:
            print(f'    data fetched: {str(rows_count)} rows')

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

    user_id = request.user_id
    log.debug(f"+++/products: user: {user_id}")

    # === Валидация и парсинг параметров ===
    try:
        req_start = max(0, int(request.args.get('start', 0)))
        req_limit = min(MAX_PAGE_LIMIT, max(1, int(request.args.get('limit', DEFAULT_PAGE_LIMIT))))  # ограничим сверху
    except ValueError:
        return jsonify({"error": "Invalid start or limit"}), 400
    
    req_category = request.args.get('category', '').strip().lower()
    if len(req_category) > 50:  # защита от слишком длинных строк
        return jsonify({"error": "Category too long"}), 400
    
    req_currency = request.args.get('currency', DEFAULT_CURRENCY).lower()
    if req_currency not in VALID_CURRENCIES:
        req_currency = DEFAULT_CURRENCY
    
    req_lang = request.args.get('lang', DEFAULT_LANG).lower()
    if req_lang not in VALID_LANGS:
        req_lang = DEFAULT_LANG
    
    col_title = f"title_{req_lang}"
    col_descr = f"descr_{req_lang}"

    log.debug(f"Params: start={req_start}, limit={req_limit}, category={req_category}, currency={req_currency}, lang={req_lang}")



    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)  # возвращает dict

        # -- важно: только активные в запросе
        base_sql = f"""
            SELECT 
                p.id AS product_id,
                c.code AS category_name,
                p.{col_title} AS product_title,
                p.{col_descr} AS product_descr,
                COALESCE(pl.price, 0) AS price,
                COALESCE(pl.stock_quantity, 0) AS quantity,
                p.code AS product_code,
                p.is_variative
            FROM products p
            LEFT JOIN categories c ON p.category_code = c.code
            LEFT JOIN price_list pl ON p.code = pl.product_code AND pl.currency_code = %s
            WHERE p.is_active = TRUE  
        """
        params = [req_currency]

        if req_category:
            base_sql += " AND c.code = %s"
            params.append(req_category)

        base_sql += f" ORDER BY c.code, p.{col_title} LIMIT %s OFFSET %s"
        params.extend([req_limit, req_start])

        
        cur.execute(base_sql, params)
        rows = cur.fetchall()
        total_fetched = len(rows)

        log.debug(f"    Fetched {total_fetched} products from DB")


        # === Получение изображений одним запросом ===
        product_codes = [row['product_code'] for row in rows]
        image_map = _fetch_image_paths_bulk(product_codes)


       # === Формирование ответа ===
        products = []
        for row in rows:
            code = row['product_code']
            products.append({
                'id'            : row['product_id'],
                'category'      : row['category_name'] or '',
                'title'         : row['product_title'] or '',
                'description'   : row['product_descr'] or '',
                'price'         : float(row['price']),
                'quantity'      : int(row['quantity']),
                'image'         : image_map.get(code, ''),
                'measure'       : '',
                'is_variative'  : bool(row['is_variative'])
            })

        response = {
            "currency"  : req_currency,
            "count"     : total_fetched,
            "start"     : req_start,
            "limit"     : req_limit,
            "products"  : products
        }

        return jsonify(response), 200

    except Exception as e:
        log.error(f"Error in get_products: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()
    



# --------------------------------------------------------------
# 📦 Запит конкретного товару
@app.route('/products/<int:product_id>', methods=['GET'])
@require_auth
def get_product(product_id):
    
    if bDebug:
        print('+++/products: user:' + str(request.user_id) + ' ; product_id:' + str(product_id))
    
    # перевірка на заповненність АйДи товару
    # product_id = request.args.get('product_id', 0)
    if product_id == 0:
        return jsonify({"message": "No product ID specified"}), 400

    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah').lower()

    # бажана мова, або Українська
    req_lang = request.args.get('lang', 'ua').lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'
    # відповідна назва колонок
    col_title = 'title_' + req_lang
    col_descr = 'descr_' + req_lang


    if bDebug:
        print('    currency:' + req_currency + '; lang:' + req_lang)

    # 1
    # отримаємо данні про товар
    try:
        # Запит до БД
        conn = get_db_connection()
        cur = conn.cursor()
        sql = """
            select 
                p.id,
                p.code,
                c.id AS category_id,
                c.code AS category,
                p.is_active AS active,
                p.""" + col_title + """ AS title,
                p.""" + col_descr + """ AS description,
                p.updated_at,
                COALESCE(pl.price, 0) AS price,
                COALESCE(pl.stock_quantity, 0) AS quantity, 
                COALESCE(ENCODE(i.img_data, 'base64'), '') AS img_data 
            FROM Products p
            LEFT JOIN categories c ON p.category_code = c.code
            LEFT JOIN price_list pl ON pl.product_code = p.code AND pl.currency_code = %s
            LEFT JOIN images i ON i.product_code = p.code
            WHERE p.id = %s"""

        cur.execute(sql, (req_currency, product_id))
        rows = cur.fetchall()
        rows_count = cur.rowcount

        product_code = rows[0][1]
        category_id  = rows[0][2]

        # Дисконнект від БД
        cur.close()
        conn.close()
        
        if bDebug:
            print('    rows fetched: ' + str(rows_count))

    except Exception as e:
        print('!!! error1: ' + str(e))
        return jsonify({"error (1): ": str(e)}), 500  # Ошибка сервера

    # має бути лише один!
    if rows_count == 0:
        return jsonify({"no records found"}), 404  # Ошибка сервера

    if rows_count != 1:
        return jsonify({"records more than expected"}), 500  # Ошибка сервера

    # отримаємо зображення товару
    try:
        # Запит до БД
        conn = get_db_connection()
        cur = conn.cursor()
        sql = """
            SELECT 
                ENCODE(i.img_data, 'base64') AS img_data 
            FROM images i
            WHERE i.product_code = %s
            ORDER BY i.id"""

        cur.execute(sql, (product_code,))
        img_rows = cur.fetchall()
        # img_count = cur.rowcount

        # Дисконнект від БД
        cur.close()
        conn.close()

    except Exception as e:
        print('!!! error2: ' + str(e))
        return jsonify({"error (2): ": str(e)}), 500  # Ошибка сервера

    try:

        # Заносимо зображення у масив
        images = []
        for row in img_rows:
            images.append({'image': row[0] or ''})
        if bDebug:
            print('    images appended.')

        # Заносимо данні
        first_row = rows[0]
        data = {
            "id": first_row[0],
            "category_id": first_row[2],
            "category": first_row[3],
            "active": first_row[4],
            "title": first_row[5],
            "description": first_row[6],
            "image": first_row[10],  # Уже закодировано в base64
            "quantity": first_row[9],
            "price": first_row[8],
            "images": images
        }
        
        if bDebug:
            print('    data packed.')

        return jsonify(data), 200


    except Exception as e:
        print('!!! error3: ' + str(e))
        return jsonify({"error (3): ": str(e)}), 500  # Ошибка сервера


# ==============================================================
# --------------------------------------------------------------
# 🛒 Запит кошика
@app.route("/cart")
@require_auth
def get_cart():
    # print('request.user_id : ', request.user_id)

    # бажана мова, або Українська
    req_lang = request.args.get('lang', 'ua').lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'

    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah').lower()

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
    req_lang = request.args.get('lang', 'ua').lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'

    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah').lower()

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
    req_lang = request.args.get('lang', 'ua').lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'

    col_title = 'title_' + req_lang


    # бажана валюта, або євро
    req_currency = request.args.get('currency', 'uah').lower()

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
            
            product_id  = item.get('id')
            quantity    = item.get('quantity')
            # price     = item.get('price')
            
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
def get_image_filepath(product_code, subprod_code, image_id):
    """
    Процедура для получения пути к вайлу изображения из таблицы images.
    Если путь не прописан - сохраняем файл на диск и прописываем.
    Параметры:
        product_code (str): Код основного товара.
        subprod_code (str or None): Код вариативного товара, если есть.
        image_id (int): ID изображения в таблице images.
    Возвращает:
        Строка - путь к файл или Пустая
    """

    if bDebug:
        print(f'+++get_image_filepath: product_code={product_code}, subprod_code={subprod_code}, image_id={image_id}')

    # Проверка на заполненность ID товара
    if not product_code:
        print(f"  * get_image_filepath error: No product code specified")
        return ""

    # Подключение к БД
    try:
        conn = get_db_connection()
        conn.autocommit = False  # manual transactions
        cursor = conn.cursor()
    except Exception as e:
        print(f"  * get_image_filepath error: Database connection error: {str(e)}")

    
    
    # Получение пути изображения
    try:
        where_SP = ""
        where_ID = ""
        if subprod_code:
            where_SP = " AND subprod_code = "+subprod_code;
        if image_id:
            where_ID = " AND id = "+image_id;

        cursor.execute("SELECT id, COALESCE(image_path,'') FROM public.images WHERE product_code = %s" + where_SP + where_ID + ";",  (product_code,) )
        image_data = cursor.fetchone()
        
        cursor.close()
        conn.close()

        image_path = ''
        if image_data:
            print(f"    image_data: {image_data}")
            image_id   = image_data[0]
            image_path = image_data[1]

        
        if image_path == '':
            print(f"  * get_image_filepath: call for save_image_to_file")
            image_path = save_image_to_file(product_code, subprod_code, image_id)
            print(f"       -- recieved in return: {image_path}")

        return image_path


    except Exception as e:
        cursor.close()
        conn.close()
        print(f"  * get_image_filepath error: Database error (fetching image): {str(e)}")
        return ""
    


# ==============================================================
# --------------------------------------------------------------
def save_image_to_file(product_code, subprod_code, image_id):
    """
    Процедура для сохранения изображения из таблицы images в файл на сервере.
    Сохраняет изображение из BYTEA в файл и обновляет поле image_path в БД.
    Параметры:
        product_code (str): Код основного товара.
        subprod_code (str or None): Код вариативного товара, если есть.
        image_id (int): ID изображения в таблице images.
    Возвращает:
        dict: Ответ с информацией об успехе/ошибке.
    """
    if bDebug:
        print(f'+++save_image_to_file: product_code={product_code}, subprod_code={subprod_code}, image_id={image_id}')

    # Проверка на заполненность ID товара
    if not product_code:
        return {"error": "No product code specified"}, 400

    # Подключение к БД
    try:
        conn = get_db_connection()
        conn.autocommit = False  # manual transactions
        cursor = conn.cursor()
    except Exception as e:
        return {"error": f"Database connection error: {str(e)}"}, 500

    # Проверка существования изображения
    try:
        if subprod_code:
            print(f'    -save_image_to_file: SELECT img_data, product_code, subprod_code FROM public.images WHERE id = {image_id} AND product_code = {product_code} AND subprod_code = {subprod_code}')
            cursor.execute(
                "SELECT img_data, product_code, subprod_code FROM public.images WHERE id = %s AND product_code = %s AND subprod_code = %s;",
                (image_id, product_code, subprod_code)
            )
        else:
            print(f'    -save_image_to_file: SELECT img_data, product_code, subprod_code FROM public.images WHERE id = {image_id} AND product_code = {product_code}')
            cursor.execute(
                "SELECT img_data, product_code, subprod_code FROM public.images WHERE id = %s AND product_code = %s;",
                (image_id, product_code)
            )
        
        image_data = cursor.fetchone()
        
        if not image_data:
            cursor.close()
            conn.close()
            return {"error": "Image not found"}, 404

        img_data, db_prod_code, db_subprod_code = image_data

        if bDebug:
            print(f"    Image found: ID={image_id}, product_code={db_prod_code}, subprod_code={db_subprod_code}")

    except Exception as e:
        cursor.close()
        conn.close()
        return {"error": f"Database error (fetching image): {str(e)}"}, 500


   # Определение типа файла по содержимому изображения
    try:
        # Если img_data — memoryview (PostgreSQL BYTEA), преобразуем в bytes
        if isinstance(img_data, memoryview):
            img_bytes = img_data.tobytes()
        else:
            img_bytes = img_data  # уже bytes (на всякий случай)

        if not img_bytes:
            raise ValueError("Image data is empty")

        file_extension = imghdr.what(None, h=img_bytes)
        if file_extension is None:
            file_extension = 'jpg'  # По умолчанию
        file_extension = f".{file_extension}"

        if bDebug:
            print(f"    Detected file type: {file_extension}")

    except Exception as e:
        cursor.close()
        conn.close()
        return {"error": f"Failed to determine image type: {str(e)}"}, 500


    # Создание директории для сохранения файлов, если не существует
    upload_folder = '/app/static/images'  # Путь к папке для хранения
    os.makedirs(upload_folder, exist_ok=True)

    # Генерация уникального имени файла
    if subprod_code:
        file_name = f"{product_code}_{subprod_code}_{image_id}{file_extension}"
    else:
        file_name = f"{product_code}_{image_id}{file_extension}"
    file_path = os.path.join(upload_folder, file_name)

    # Сохранение изображения в файл
    try:
        with open(file_path, 'wb') as f:
            f.write(img_data)
        #if bDebug:
        print(f"    Image saved to file: {file_path}")
    except Exception as e:
        cursor.close()
        conn.close()
        return {"error": f"Failed to save image to file: {str(e)}"}, 500

    # Обновление поля image_path в таблице images
    try:
        cursor.execute(
            "UPDATE public.images SET image_path = %s, img_data='' WHERE id = %s;",
            (file_path, image_id)
        )
        conn.commit()
        if bDebug:
            print(f"    Image path updated in DB: {file_path}")
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return {"error": f"Database error (updating path): {str(e)}"}, 500

    finally:
        cursor.close()
        conn.close()

    # Формирование ответа
    response = {
        "message": "Image saved to file and path updated successfully",
        "image_id": image_id,
        "product_code": product_code,
        "file_path": file_path
    }
    if subprod_code:
        response["subprod_code"] = subprod_code

    return response, 200



def _fetch_image_paths_bulk(product_codes: List[str]) -> Dict[str, str]:
    """
    Получает пути к изображениям для списка product_code одним запросом.
    Возвращает dict: {product_code: image_path}
    """
    if not product_codes:
        return {}

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Используем IN с параметрами
        placeholders = ','.join(['%s'] * len(product_codes))
        query = f"""
            SELECT product_code, COALESCE(image_path, '') AS image_path
            FROM public.images
            WHERE product_code IN ({placeholders})
              AND (subprod_code IS NULL OR subprod_code = '')
              AND image_path IS NOT NULL
            GROUP BY product_code, image_path  -- на случай дубликатов
        """
        cur.execute(query, product_codes)
        rows = cur.fetchall()

        # Формируем словарь
        image_map = {row[0]: row[1] for row in rows}

        # Для отсутствующих — попробуем сохранить (опционально)
        missing_codes = [code for code in product_codes if code not in image_map]
        if missing_codes:
            log.debug(f"Missing images for {len(missing_codes)} products, calling save_image_to_file")
            for code in missing_codes:
                path = save_image_to_file(code, None, None)
                if path:
                    image_map[code] = path
                    # Опционально: обновить БД
                    try:
                        cur.execute(
                            "INSERT INTO public.images (product_code, image_path) VALUES (%s, %s) "
                            "ON CONFLICT (product_code) WHERE subprod_code IS NULL DO UPDATE SET image_path = EXCLUDED.image_path",
                            (code, path)
                        )
                    except Exception as e:
                        log.warning(f"Failed to cache image path for {code}: {e}")

        conn.commit()
        return image_map

    except Exception as e:
        log.error(f"Error in _fetch_image_paths_bulk: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return {}
    finally:
        if conn:
            conn.close()



# Новый роут для публичного доступа к изображениям
@app.route('/images/<path:filename>')  # /images/data/images/product_123.jpg
def get_image(filename):
    # Проверяем, чтобы избежать path traversal (безопасность)
    if '..' in filename or filename.startswith('/'):
        return "Forbidden", 403
    return send_from_directory('/app/static/images', filename)  # Отдаёт из volume



# ==============================================================
# --------------------------------------------------------------
# Запуск приложения (локально или на хостинге)

if __name__ == "main":
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

# flask-rlwai
