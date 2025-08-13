import os
import psycopg2    # PostgreSQL
import secrets
import time
import bcrypt
from flask import Flask, jsonify, request
from functools import wraps
from dotenv import load_dotenv    # Для загрузки переменных окружения из .env файла


# Если приложение запущено локально, а не в Railway — загружаем переменные из .env
if os.environ.get("RAILWAY_ENVIRONMENT") is None:
    load_dotenv()

app = Flask(__name__)




# ==============================================================
# --------------------------------------------------------------
# 🔐 Звичайна база користувачів та токенів
USERS = {"admin": "1234"}
TOKENS = {}  # token -> (username, expiry)
TOKEN_TTL = 172800  # 48 годин



# --------------------------------------------------------------
# 🔐 Декоратор авторизації

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({"error": "Authorization header missing"}), 401

        token = auth.split(' ')[1]
        user_data = TOKENS.get(token)

        if not user_data:
            return jsonify({"error": "Invalid or expired token"}), 401

        username, expiry = user_data
        if time.time() > expiry:
            del TOKENS[token]
            return jsonify({"error": "Token expired"}), 401

        request.user = username
        return f(*args, **kwargs)
    return decorated



# --------------------------------------------------------------
# 🔐 Точка входу для отримання токену
@app.route('/login', methods=['POST'])

def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    if USERS.get(username) != password:
        return jsonify({"error": "Invalid credentials"}), 401

    token = secrets.token_hex(16)
    TOKENS[token] = (username, time.time() + TOKEN_TTL)

    return jsonify({"token": token})





# ==============================================================
# --------------------------------------------------------------
# 💾 Функція підключення до БД, викликається з кожного маршруту, де потрібно звертатися до бази

def get_db_connection():
    db_url = os.getenv("DATABASE_URL")   # Читаем URL базы из переменной окружения
    if not db_url:
        raise RuntimeError("DATABASE_URL не задана.")
    return psycopg2.connect(db_url)




# ==============================================================
# --------------------------------------------------------------
# 📦 Запит списку товарів
# Когда ты стучишься к аппке GET-запросом по адресу https://<аппка>/products
# то вызывается функция, которая описана непосредственно под определением роута "@app.route('/products', methods=['GET'])" 
# В нашем случае - get_products()
# Так во фласке построена вся маршрутизация
@app.route('/products', methods=['GET'])
@require_auth

def get_products():
    # Получаем параметры запроса
    # это именно GET-параметры - request.args.get(param name)
    # как работать с POST описал в комментах в create_order()

    req_start = request.args.get('start')
    req_limit = request.args.get('limit')

    req_category = request.args.get('category')
    #category_type = type(req_category)
    
        
    req_currency = request.args.get('currency', 'uah')
    req_currency = req_currency.lower()
    if req_currency == '':
        req_currency = 'uah'
        
    req_lang = request.args.get('lang', 'ua')
    req_lang = req_lang.lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'
    
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
            INNER JOIN categories c ON p.category_id = c.id
            INNER JOIN price_list pl ON p.id = pl.product_id AND pl.currency_code = %s"""
        
        # Это параметризирванные запросы, защита от инъекций в SQL
        # В тексте SQL ставишь параметры типа %s и кодом "params = [currency, lang]" запихиваешь их в список
        #params = [currency, lang]
        params = [req_currency]
        
        if req_category:
            # И добавляешь в список параметров SQL-запроса
            params.append(req_category)
            
            if isinstance(req_category, str) == True:
                sql += "    WHERE c.code = %s"
            else:
                sql += "    WHERE c.id = %s"
        
        sql += "    ORDER BY c.code, p."+col_title
        
        
        # При выполнении запроса либа проверит и подставит твои параметры запроса
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
            "currency"  : req_currency,
            "count"     : rows_count,
            "start"     : req_start,
            "limit"     : req_limit,
            "products"  : products 
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
    #product_id = request.args.get('product_id', 0)
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
                p."""+col_title+""" as title,
                p."""+col_descr+""" as description,
                p.updated_at,
                pl.price,
                pl.stock_quantity,
                i.img_data
            from Products p
            inner join categories c ON p.category_id = c.id
            inner join price_list pl ON pl.product_id = p.id AND pl.currency_code = '"""+req_currency+"""'
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
        #img_count = cur.rowcount
        
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
            "id"            : first_row[0],
            "category_id"   : first_row[1],
            "category"      : first_row[2],
            "active"        : first_row[3],
            "title"         : first_row[4],
            "description"   : first_row[5],
            "image"         : first_row[9],
            "quantity"      : first_row[8],
            "price"         : first_row[7],
            "images"        : images 
        }
        
        
        return jsonify(data), 200
        
        
    except Exception as e:
        return jsonify({"error (3): ": str(e)}), 500  # Ошибка сервера
    
    
    
    
    
# ==============================================================
# --------------------------------------------------------------
@app.route('/orders', methods=['POST'])
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
    
    if not data or 'customer_id' not in data or 'items' not in data:
        return jsonify({"error": "Missing data"}), 400  # Проверка наличия данных
    
    customer_id = data['customer_id']
    items = data['items']
    
    if not items or not isinstance(items, list):
        return jsonify({"error": "Items list is required"}), 400  # Проверка структуры
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Вставляем заказ и получаем его ID
        cursor.execute(
            "INSERT INTO orders (customer_id, invoice_date) VALUES (%s, CURRENT_TIMESTAMP) RETURNING order_id;",
            (customer_id,)
        )
        order_id = cursor.fetchone()[0]
        
        for item in items:
            product_id = item.get('product_id')
            quantity = item.get('quantity')
            price = item.get('price')
            
            if not all([product_id, quantity, price]):
                continue  # Пропускаем неполные строки

            cursor.execute(
                "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (%s, %s, %s, %s);",
                (order_id, product_id, quantity, price)
            )
            
        conn.commit()  # Сохраняем изменения
        cursor.close()
        conn.close()
        
        return jsonify({"message": "Order created successfully", "order_id": order_id}), 201
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/orders', methods=['GET'])
@require_auth

def get_orders():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Запрос с объединением заказов и их позиций
        cursor.execute("""
            SELECT o.order_id, o.customer_id, o.invoice_date, 
                   oi.order_item_id, oi.product_id, oi.quantity, oi.price,
                   pn.name as product_name
            FROM orders o
            LEFT JOIN order_items oi ON o.order_id = oi.order_id
            LEFT JOIN product_names pn ON oi.product_id = pn.product_id AND pn.lang_id = 'ua';
        """)

        orders = cursor.fetchall()

        if orders:
            orders_list = []
            current_order = None
            for order in orders:
                order_id, customer_id, invoice_date, order_item_id, product_id, quantity, price, product_name = order
                if current_order != order_id:
                    if current_order is not None:
                        orders_list.append(current_order_data)
                    current_order_data = {
                        "order_id": order_id,
                        "customer_id": customer_id,
                        "invoice_date": invoice_date,
                        "items": []
                    }
                    current_order = order_id

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
            return jsonify({"orders": orders_list}), 200
        
        
        cursor.close()
        conn.close()
        return jsonify({"message": "No orders found"}), 404
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# --------------------------------------------------------------
@app.route("/languages")
@require_auth

def get_languages():
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
            "count"     :   rows_count,
            "languages" :   datarows
        }
        
        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# --------------------------------------------------------------
@app.route("/currencies")
@require_auth

def get_currencies():

    lang = request.args.get('lang', 'ua')
    lang = lang.lower()
    if lang not in ['ua', 'pl', 'en', 'ru']:
        lang = 'ua'
    
    col_title = 'title_'+lang
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT code, " +col_title+ " FROM public.currencies ORDER BY code;")
        
        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()

        datarows = [
            {"code": row[0].strip(), "title": row[1]}
            for row in rows
        ]
        
        data = {
            "count"     :   rows_count,
            "currencies":   datarows
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

    lang = request.args.get('lang', 'ua')
    lang = lang.lower()
    if lang not in ['ua', 'pl', 'en', 'ru']:
        lang = 'ua'
    
    col_title = 'title_'+lang
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        #cur.execute("SELECT id, code, " + col_title + " FROM public.categories ORDER BY id;")
        cur.execute("""
            SELECT 
            	c.id, 
            	c.code, 
            	c.""" + col_title + """, 
            	COUNT(p.id) as ProductCount
            FROM 
                Categories c
            LEFT JOIN 
                Products p ON c.id = p.category_id
            GROUP BY 
                c.id, c.title_ru 
            ORDER BY c.id;""")

        
        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()
        
        datarows = [
            {"id": row[0], "code": row[1].strip(), "title": row[2], "prod_count": row[3]}
            for row in rows
        ]
        
        data = {
            "count"     :   rows_count,
            "categories":   datarows
        }
        
        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




# ==============================================================
# --------------------------------------------------------------
# 🛒 Запит кошика
@app.route("/cart")
@require_auth

def get_cart():
    
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
        #cur.execute("SELECT id, code, " + col_title + " FROM public.categories ORDER BY id;")
        
        sql = """
            select 
                c.id,
                c.customer_id,
                c.product_id,
                pr.category_id,
                cat.code,
                pr."""+col_title+""" as title,
                pr."""+col_descr+""" as description,
                i.img_data,
                c.quantity,
                pl.price,
                c.quantity * pl.price as summ 
            from carts c 
            inner join products pr ON pr.id = c.product_id
            inner join price_list pl ON pl.product_id = c.product_id AND pl.currency_code = '"""+req_currency+"""'
            inner join categories cat ON cat.id = pr.category_id
            left join images i ON i.product_id = c.product_id
            where c.customer_id = 11"""
        
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
        
        for row in rows:
            
            productsdata = [
                {"id"       : row[2],
                 "category" : row[4].strip(),
                 "title"    : row[5].strip(),
                 "image"    : row[7],
                 "measure"  : "шт.",
                 "quantity" : row[8],
                 "price"    : row[9],
                 "summ"     : row[10]
                }
            ]
            
            total_summ = total_summ + row[10]
        
        
        data = {
            "count"     :   rows_count,
            "total"     :   total_summ,
            "products"  :   productsdata
        }
        
        return jsonify(data), 200

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
