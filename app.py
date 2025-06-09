import os
import psycopg2    # PostgreSQL
from flask import Flask, jsonify, request
from dotenv import load_dotenv    # Для загрузки переменных окружения из .env файла

# Если приложение запущено локально, а не в Railway — загружаем переменные из .env
if os.environ.get("RAILWAY_ENVIRONMENT") is None:
    load_dotenv()

app = Flask(__name__)


# --------------------------------------------------------------
# функция коннекта в БД, вызывается из каждого роута, где надо обращаться к базе
def get_db_connection():
    db_url = os.getenv("DATABASE_URL")   # Читаем URL базы из переменной окружения
    if not db_url:
        raise RuntimeError("DATABASE_URL не задана.")
    return psycopg2.connect(db_url)



# Когда ты стучишься к аппке GET-запросом по адресу https://<аппка>/products
# то вызывается функция, которая описана непосредственно под определением роута "@app.route('/products', methods=['GET'])" 
# В нашем случае - get_products()
# Так во фласке построена вся маршрутизация
# --------------------------------------------------------------
@app.route('/products', methods=['GET'])
def get_products():
    # Получаем параметры запроса
    # это именно GET-параметры - request.args.get(param name)
    # как работать с POST описал в комментах в create_order()

    req_start = request.args.get('start')
    req_limit = request.args.get('limit')

    req_category = request.args.get('category')
    
    req_currency = request.args.get('currency', 'eur')
    req_currency = req_currency.lower()
    if req_currency == '':
        req_currency = 'eur'
        
    req_lang = request.args.get('lang', 'ua')
    req_lang = req_lang.lower()
    if req_lang not in ['ua', 'pl', 'en', 'ru']:
        req_lang = 'ua'
    
    col_title = 'title_' + req_lang

    
    try:
        # Запрос к БД
        conn = get_db_connection()
        cur = conn.cursor()

        #sql = """
        #    SELECT 
        #        p.id AS product_id,
        #        pn.name AS product_name,
        #        c.name AS category_name,
        #        pl.price,
        #        pl.stock_quantity,
        #        pl.currency_id
        #    FROM products p
        #    INNER JOIN product_names pn ON p.id = pn.product_id
        #    INNER JOIN categories c ON p.category_id = c.id
        #    INNER JOIN price_list pl ON p.id = pl.product_id AND pl.currency_id = %s
        #    WHERE pn.lang_id = %s
        #"""

        sql = """
            SELECT 
                p.id AS product_id,
                c.code AS category_code,
                p.""" + col_title + """ AS product_title,
                pl.price,
                pl.stock_quantity
            FROM products p
            INNER JOIN categories c ON p.category_id = c.id
            INNER JOIN price_list pl ON p.id = pl.product_id AND pl.currency_code = %s
        """
        
        # Это параметризирванные запросы, защита от инъекций в SQL
        # В тексте SQL ставишь параметры типа %s и кодом "params = [currency, lang]" запихиваешь их в список
        #params = [currency, lang]
        params = [req_currency]

        if req_category:
            sql += " AND c.code = %s"
            # И добавляешь в список параметров SQL-запроса
            params.append(req_category)

        #sql += " ORDER BY c.name, p.id"
        sql += " ORDER BY c.code, p."+col_title

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
        else:
            return jsonify({"message": "No products found"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Ошибка сервера



# --------------------------------------------------------------
@app.route('/orders', methods=['POST'])
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
        else:
            cursor.close()
            conn.close()
            return jsonify({"message": "No orders found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# --------------------------------------------------------------
@app.route("/languages")
def get_languages():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        #cur.execute("SELECT id, code, title FROM public.languages ORDER BY id;")
        cur.execute("SELECT code, title FROM public.languages ORDER BY id;")
        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()

        datarows = [
            {"code": row[0].strip(), "title": row[1]}
            for row in rows
        ]
        #{"id": row[0], "code": row[1].strip(), "title": row[2]}

        data = {
            "count"     :   rows_count,
            "languages" :   datarows
        }
        
        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



# --------------------------------------------------------------
@app.route("/currencies")
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



# --------------------------------------------------------------
@app.route("/categories")
def get_categories():

    lang = request.args.get('lang', 'ua')
    lang = lang.lower()
    if lang not in ['ua', 'pl', 'en', 'ru']:
        lang = 'ua'
    
    col_title = 'title_'+lang
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, code, " + col_title + " FROM public.categories ORDER BY id;")
        
        rows = cur.fetchall()
        rows_count = cur.rowcount
        cur.close()
        conn.close()
        
        datarows = [
            {"id": row[0], "code": row[1].strip(), "title": row[2], "prod_count": 0}
            for row in rows
        ]
        
        data = {
            "count"     :   rows_count,
            "categories":   datarows
        }
        
        return jsonify(data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



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
