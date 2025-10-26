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

# Настройка логирования (замена print)
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

bDebug = False
bDebug2= False

# === Константи ===
VALID_LANGS         = {'ua', 'pl', 'en', 'ru'}
VALID_CURRENCIES    = {'uah', 'pln', 'usd', 'eur'}
DEFAULT_LANG        = 'ua'
DEFAULT_CURRENCY    = 'uah'
DEFAULT_PAGE_LIMIT  = 50
MAX_PAGE_LIMIT      = 250
NO_IMAGE_MARKER     = "__NO_IMAGE__"  # Маркер: изображения нет и не нужно искать
UPLOAD_FOLDER       = "/app/static/images"

# === Типи ===
ImageKey        = Tuple[str, Optional[str]]  # (product_code, subprod_code)
ImagePathMap    = Dict[ImageKey, str]


app = Flask(__name__)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)




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
        items = [(row['product_code'], None) for row in rows]  # subprod_code = None
        image_map = _fetch_image_paths_bulk(items)
        

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
                'image'         : image_map.get((code, None), ''),
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
def _parse_product_str(product_str: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Разбирает строку вида "123" или "123|VAR001"
    Возвращает (product_id, subprod_code)
    """
    if not product_str:
        return None, None

    parts = product_str.strip().split('|', 1)
    try:
        product_id = int(parts[0])
    except ValueError:
        return None, None

    subprod_code = parts[1] if len(parts) > 1 and parts[1].strip() else None
    return product_id, subprod_code


@app.route('/products/<string:product_str>', methods=['GET'])
@require_auth
def get_product(product_str: str):
    user_id = request.user_id
    log.debug(f"+++/products/{product_str}: user: {user_id}")

    # === 1. Парсинг product_str ===
    product_id, subprod_code = _parse_product_str(product_str)
    if product_id is None:
        return jsonify({"error": "Invalid product identifier"}), 400

    log.debug(f"Parsed: product_id={product_id}, subprod_code={subprod_code}")

    # === 2. Валидация параметров ===
    req_currency = request.args.get('currency', DEFAULT_CURRENCY).lower()
    if req_currency not in VALID_CURRENCIES:
        req_currency = DEFAULT_CURRENCY

    req_lang = request.args.get('lang', DEFAULT_LANG).lower()
    if req_lang not in VALID_LANGS:
        req_lang = DEFAULT_LANG

    col_title = f"title_{req_lang}"
    col_descr = f"descr_{req_lang}"

    # === 3. Запрос товара (только по product_id) ===
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        sql = f"""
            SELECT 
                p.id,
                p.code AS product_code,
                c.id AS category_id,
                c.code AS category,
                p.is_active,
                p.{col_title} AS title,
                p.{col_descr} AS description,
                p.updated_at,
                COALESCE(pl.price, 0) AS price,
                COALESCE(pl.stock_quantity, 0) AS quantity
            FROM products p
            LEFT JOIN categories c ON p.category_code = c.code
            LEFT JOIN price_list pl ON p.code = pl.product_code AND pl.currency_code = %s
            WHERE p.id = %s AND p.is_active = TRUE
        """
        cur.execute(sql, (req_currency, product_id))
        row = cur.fetchone()

        if not row:
            return jsonify({"error": "Product not found"}), 404

        product_code = row['product_code']

        # === 4. Изображения через _fetch_image_paths_bulk ===
        # Определяем, какое изображение главное
        main_key = (product_code, subprod_code)  # приоритет: subprod_code
        fallback_key = (product_code, None)

        # Запрашиваем оба (или один)
        image_keys = [main_key]
        if subprod_code:
            image_keys.append(fallback_key)  # если нет по subprod_code → по основному

        image_map = _fetch_image_paths_bulk(image_keys)

        # Главное изображение
        main_image = image_map.get(main_key) or image_map.get(fallback_key, '')

        # Все изображения (основные + вариативные)
        all_images = []
        # Основное
        if image_map.get(fallback_key):
            all_images.append(image_map[fallback_key])
        # Вариативное (если есть)
        if subprod_code and image_map.get(main_key):
            all_images.append(image_map[main_key])

        # === 5. Формируем ответ ===
        response = {
            "id": row['id'],
            "product_code": product_code,
            "category_id": row['category_id'],
            "category": row['category'],
            "active": row['is_active'],
            "title": row['title'] or '',
            "description": row['description'] or '',
            "price": float(row['price']),
            "quantity": int(row['quantity']),
            "image": main_image,
            "images": all_images,
            "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None
        }

        if subprod_code:
            response["subprod_code"] = subprod_code

        return jsonify(response), 200

    except Exception as e:
        log.error(f"Error in get_product: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()
    


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
def save_image_to_file( product_code: str,   subprod_code: Optional[str],   image_id: int,   img_data: bytes ) -> str:
    """
    Сохраняет BYTEA в файл и обновляет image_path в БД.
    Возвращает путь к файлу или ''.
    """

    try:
        # --- 1. Определяем расширение ---
        file_ext = imghdr.what(None, h=img_data)
        file_ext = f".{file_ext}" if file_ext else ".jpg"

        # --- 2. Формируем путь ---
        suffix = f"_{subprod_code}" if subprod_code else ""
        filename = f"{product_code}{suffix}_{image_id}{file_ext}"
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # --- 3. Сохраняем на диск ---
        with open(file_path, "wb") as f:
            f.write(img_data)

        # --- 4. Обновляем БД ---
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE public.images
                    SET image_path = %s, img_data = NULL
                    WHERE id = %s
                """, (file_path, image_id))
            conn.commit()
        except Exception as e:
            conn.rollback()
            log.warning(f"DB update failed for image {image_id}: {e}")
        finally:
            conn.close()

        log.debug(f"Image saved: {file_path}")
        return file_path

    except Exception as e:
        log.warning(f"Failed to save image {product_code}/{subprod_code} (id={image_id}): {e}")
        return ""




def _fetch_image_paths_bulk(  items: List[ImageKey]  ) -> ImagePathMap:
    """
    Возвращает пути к изображениям для списка [(product_code, subprod_code), ...].
    Сортирует по is_primary DESC.
    """

    if not items:
        return {}

    # Убираем дубли
    unique_items = list(dict.fromkeys(items))
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:

            # --- 1. Формируем запрос: только нужные + с img_data или без пути ---
            placeholders = ','.join('(%s, %s)' for _ in unique_items)
            params = [code for code, sub in unique_items for code in [code, sub or '']]

            query = f"""
                SELECT 
                    product_code,
                    subprod_code,
                    image_path,
                    img_data,
                    id,
                    is_primary
                FROM public.images
                WHERE (product_code, COALESCE(subprod_code, '')) IN ({placeholders})
                  AND (
                    image_path IS NULL OR image_path = '' OR image_path = %s
                  )
                ORDER BY is_primary DESC, id
            """
            cur.execute(query, params + [NO_IMAGE_MARKER])
            rows = cur.fetchall()

        # --- 2. Обрабатываем результаты ---
        result_map: ImagePathMap = {}
        to_save = []  # (id, code, sub, img_data)

        for code, sub, path, img_data, img_id, is_primary in rows:
            key: ImageKey = (code, sub if sub else None)

            # Если путь уже есть и не маркер — используем
            if path and path != NO_IMAGE_MARKER and os.path.exists(path):
                result_map[key] = path
                continue

            # Если есть img_data — нужно сохранить
            if img_data:
                if isinstance(img_data, memoryview):
                    img_data = img_data.tobytes()
                to_save.append((img_id, code, sub if sub else None, img_data))
            else:
                # Нет данных и нет пути → маркер
                result_map[key] = ''
                _mark_no_image(conn, img_id)

        # --- 3. Сохраняем изображения ---
        for img_id, code, sub, img_data in to_save:
            key: ImageKey = (code, sub)
            saved_path = save_image_to_file(code, sub, img_id, img_data)
            result_map[key] = saved_path or ''

        # --- 4. Для остальных — возвращаем '' (и маркер в БД) ---
        for code, sub in unique_items:
            key: ImageKey = (code, sub)
            if key not in result_map:
                result_map[key] = ''
                # Найдём id и пометим
                img_id = _get_image_id(conn, code, sub)
                if img_id:
                    _mark_no_image(conn, img_id)

        return result_map

    except Exception as e:
        log.error(f"_fetch_image_paths_bulk error: {e}", exc_info=True)
        return {item: '' for item in unique_items}
    finally:
        if conn:
            conn.close()


def _get_image_id(conn, product_code: str, subprod_code: Optional[str]) -> Optional[int]:
    """Возвращает id записи или None"""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id FROM public.images
                WHERE product_code = %s AND COALESCE(subprod_code, '') = %s
                LIMIT 1
            """, (product_code, subprod_code or ''))
            row = cur.fetchone()
            return row[0] if row else None
    except:
        return None


def _mark_no_image(conn, image_id: int):
    """Ставит __NO_IMAGE__"""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE public.images SET image_path = %s WHERE id = %s
            """, (NO_IMAGE_MARKER, image_id))
        conn.commit()
    except:
        conn.rollback()
    



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
