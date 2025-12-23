# app.py
"""
Основной файл приложения Flask для тестирования.
Этот код реализует серверную часть веб-приложения тестирования.
"""
from functools import wraps
import hashlib
import secrets
import time
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
import json
import os
from datetime import datetime
import logging
# Загрузка переменных окружения
from dotenv import load_dotenv
load_dotenv()  # Загружает переменные из файла .env


# Настройки безопасности
MAX_LOGIN_ATTEMPTS = 3
LOGIN_BLOCK_TIME = 300  # 5 минут в секундах
PASSWORD_MIN_LENGTH = 8



# Словарь для хранения неудачных попыток входа
failed_attempts = {}


# Функция для генерации хэша пароля
def hash_password(password, salt=None):
    """Хэширование пароля с солью"""
    if salt is None:
        salt = secrets.token_hex(16)

    # Создаем хэш пароля
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Количество итераций
    )

    return f"{salt}:{key.hex()}"


# Функция для проверки пароля
def verify_password(stored_password, provided_password):
    """Проверка пароля"""
    if ':' not in stored_password:
        return False

    salt, hashed_password = stored_password.split(':')

    # Хэшируем предоставленный пароль с той же солью
    new_hash = hash_password(provided_password, salt)

    # Сравниваем хэши
    return secrets.compare_digest(stored_password, new_hash)


# Проверка сложности пароля
def check_password_strength(password):
    """Проверка сложности пароля"""
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Пароль должен быть не менее {PASSWORD_MIN_LENGTH} символов"

    # Проверяем наличие цифр
    if not any(char.isdigit() for char in password):
        return False, "Пароль должен содержать хотя бы одну цифру"

    # Проверяем наличие букв в разных регистрах
    if not any(char.isupper() for char in password):
        return False, "Пароль должен содержать хотя бы одну заглавную букву"

    if not any(char.islower() for char in password):
        return False, "Пароль должен содержать хотя бы одну строчную букву"

    return True, "Пароль соответствует требованиям"


# Декоратор для проверки блокировки IP
def check_ip_block(f):
    """Проверка блокировки IP адреса"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr

        # Проверяем, не заблокирован ли IP
        if client_ip in failed_attempts:
            attempts_data = failed_attempts[client_ip]

            # Проверяем время блокировки
            if attempts_data['blocked_until'] and attempts_data['blocked_until'] > time.time():
                remaining_time = int(attempts_data['blocked_until'] - time.time())
                return render_template('admin_login.html',
                                       error=f"Слишком много неудачных попыток. Повторите через {remaining_time // 60} минут {remaining_time % 60} секунд.")

        return f(*args, **kwargs)

    return decorated_function


# Обновим функцию log_action для записи IP адресов
def log_action(username, action):
    """Функция для логирования действий пользователя"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = request.remote_addr if 'request' in globals() else '127.0.0.1'

    log_entry = f"{timestamp} - IP: {client_ip} - Пользователь: {username} - Действие: {action}"
    logging.info(log_entry)

    # Также сохраняем в JSON файл для удобного просмотра
    json_log = {
        'date': datetime.now().strftime("%Y-%m-%d"),
        'time': datetime.now().strftime("%H:%M:%S"),
        'ip': client_ip,
        'user': username,
        'action': action
    }

    try:
        with open('user_actions.json', 'a', encoding='utf-8') as f:
            f.write(json.dumps(json_log, ensure_ascii=False) + '\n')
    except:
        pass


# Обновим декоратор admin_required для дополнительной безопасности
def admin_required(f):
    """Декоратор для защиты административных страниц с проверкой таймаута"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Проверяем, авторизован ли администратор
        if not session.get('is_admin'):
            # Если нет, показываем форму входа
            return redirect(url_for('admin_login'))

        # Проверяем таймаут сессии (30 минут)
        last_activity = session.get('last_activity')
        if last_activity:
            if time.time() - last_activity > 1800:  # 30 минут
                session.clear()
                return redirect(url_for('admin_login'))

        # Обновляем время последней активности
        session['last_activity'] = time.time()

        return f(*args, **kwargs)

    return decorated_function


# Функция для регистрации неудачной попытки входа
def register_failed_attempt(ip_address):
    """Регистрация неудачной попытки входа"""
    if ip_address not in failed_attempts:
        failed_attempts[ip_address] = {
            'attempts': 0,
            'last_attempt': 0,
            'blocked_until': None
        }

    data = failed_attempts[ip_address]
    data['attempts'] += 1
    data['last_attempt'] = time.time()

    # Если 3 неудачные попытки, блокируем на 5 минут
    if data['attempts'] >= MAX_LOGIN_ATTEMPTS:
        data['blocked_until'] = time.time() + LOGIN_BLOCK_TIME
        log_action('SYSTEM', f'IP {ip_address} заблокирован на {LOGIN_BLOCK_TIME // 60} минут')

    # Очищаем старые записи (старше 1 часа)
    cleanup_failed_attempts()


# Функция для очистки старых записей о неудачных попытках
def cleanup_failed_attempts():
    """Очистка старых записей о неудачных попытках входа"""
    current_time = time.time()
    ips_to_remove = []

    for ip, data in failed_attempts.items():
        # Если с последней попытки прошло больше часа и IP не заблокирован
        if (current_time - data['last_attempt'] > 3600 and
                (data['blocked_until'] is None or current_time > data['blocked_until'])):
            ips_to_remove.append(ip)

    for ip in ips_to_remove:
        del failed_attempts[ip]



app = Flask(__name__)
app.secret_key = 'test_app_secret_key'  # Секретный ключ для сессий

# Настройка логирования действий пользователя
logging.basicConfig(filename='user_actions.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# Файл для хранения вопросов
QUESTIONS_FILE = 'data/questions.json'
RESULTS_FILE = 'data/results.json'


# Конфигурация администратора
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'


def log_action(username, action):
    """Функция для логирования действий пользователя"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - Пользователь: {username} - Действие: {action}"
    logging.info(log_entry)

    # Также сохраняем в JSON файл для удобного просмотра
    json_log = {
        'date': datetime.now().strftime("%Y-%m-%d"),
        'time': datetime.now().strftime("%H:%M:%S"),
        'user': username,
        'action': action
    }

    try:
        with open('user_actions.json', 'a', encoding='utf-8') as f:
            f.write(json.dumps(json_log, ensure_ascii=False) + '\n')
    except:
        pass


def load_questions():
    """Загрузка вопросов из JSON файла"""
    if not os.path.exists(QUESTIONS_FILE):
        # Создаем тестовые вопросы, если файла нет
        default_questions = [
            {
                "id": 1,
                "question": "Что такое HTML?",
                "options": ["Язык программирования", "Язык разметки", "База данных", "Фреймворк"],
                "correct": 1,
                "visible": True
            },
            {
                "id": 2,
                "question": "Что такое CSS?",
                "options": ["Язык программирования", "Каскадные таблицы стилей", "База данных", "Операционная система"],
                "correct": 1,
                "visible": True
            },
            {
                "id": 3,
                "question": "Что такое JavaScript?",
                "options": ["Язык разметки", "Язык программирования", "База данных", "Текстовый редактор"],
                "correct": 1,
                "visible": True
            }
        ]
        os.makedirs('data', exist_ok=True)
        with open(QUESTIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_questions, f, ensure_ascii=False, indent=2)
        return default_questions

    with open(QUESTIONS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_results(username, answers, score):
    """Сохранение результатов теста"""
    result = {
        'username': username,
        'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'answers': answers,
        'score': score,
        'total': len(answers)
    }

    try:
        if os.path.exists(RESULTS_FILE):
            with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = []

        results.append(result)

        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    except:
        pass

# Функция для администрирования
def admin_required(f):
    """Декоратор для защиты административных страниц"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Проверяем, авторизован ли администратор
        if not session.get('is_admin'):
            # Если нет, показываем форму входа
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)

    return decorated_function


# Маршрут для входа администратора
@app.route('/admin/login', methods=['GET', 'POST'])
@check_ip_block
def admin_login():
    """Страница входа для администратора"""
    error = None

    # Очищаем старые записи о неудачных попытках
    cleanup_failed_attempts()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        client_ip = request.remote_addr

        # Логируем попытку входа
        log_action(username, f'Попытка входа в административную панель с IP {client_ip}')

        # Получаем учетные данные из переменных окружения
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_password_hash = os.environ.get('ADMIN_PASSWORD_HASH')

        # Если хэш пароля не задан, используем тестовый пароль (только для разработки!)
        if admin_password_hash is None:
            # Только для разработки - в продакшене всегда используйте переменные окружения!
            admin_password_hash = hash_password('admin123')

        # Проверяем логин и пароль
        if username == admin_username and verify_password(admin_password_hash, password):
            # Сбрасываем счетчик неудачных попыток для этого IP
            if client_ip in failed_attempts:
                failed_attempts.pop(client_ip, None)

            # Устанавливаем флаг администратора в сессии
            session['is_admin'] = True
            session['admin_username'] = username
            session['login_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            session['last_activity'] = time.time()
            session['ip_address'] = client_ip

            # Устанавливаем secure cookies для HTTPS
            session.permanent = True

            # Логируем успешный вход
            log_action(username, 'Успешный вход в административную панель')

            return redirect(url_for('admin_questions'))
        else:
            # Регистрируем неудачную попытку
            register_failed_attempt(client_ip)

            error = 'Неверное имя пользователя или пароль'
            log_action(username, 'Неудачная попытка входа в админку')

    return render_template('admin_login.html', error=error)


# Маршрут для выхода администратора
@app.route('/admin/logout')
@admin_required
def admin_logout():
    """Выход из административной панели"""
    username = session.get('admin_username', 'Администратор')
    client_ip = session.get('ip_address', 'неизвестен')

    # Логируем выход
    log_action(username, f'Выход из административной панели с IP {client_ip}')

    # Полная очистка сессии
    session.clear()

    return redirect(url_for('index'))


# Маршрут для смены пароля (дополнительная функция)
@app.route('/admin/change-password', methods=['GET', 'POST'])
@admin_required
def change_password():
    """Страница для смены пароля администратора"""
    error = None
    success = None

    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Получаем текущий хэш пароля
        current_password_hash = os.environ.get('ADMIN_PASSWORD_HASH')

        # Проверяем текущий пароль
        if not verify_password(current_password_hash, current_password):
            error = 'Текущий пароль неверен'
        elif new_password != confirm_password:
            error = 'Новые пароли не совпадают'
        else:
            # Проверяем сложность нового пароля
            is_strong, message = check_password_strength(new_password)
            if not is_strong:
                error = message
            else:
                # Генерируем новый хэш пароля
                new_password_hash = hash_password(new_password)

                # В реальном приложении здесь нужно сохранить новый хэш
                # Например, в файл конфигурации или базу данных
                # Для простоты выводим новый хэш
                success = f'Новый хэш пароля: {new_password_hash}'

                # Логируем смену пароля
                username = session.get('admin_username', 'Администратор')
                log_action(username, 'Попытка смены пароля')

    return render_template('admin_change_password.html',
                           error=error,
                           success=success,
                           username=session.get('admin_username'))


# Маршрут для просмотра активности сессии
@app.route('/admin/session-info')
@admin_required
def session_info():
    """Информация о текущей сессии"""
    session_data = {
        'username': session.get('admin_username'),
        'login_time': session.get('login_time'),
        'last_activity': session.get('last_activity'),
        'ip_address': session.get('ip_address'),
        'session_id': request.cookies.get('session'),
        'time_remaining': 1800 - (time.time() - session.get('last_activity', 0))
    }

    return render_template('admin_session_info.html',
                           session_data=session_data,
                           username=session.get('admin_username'))

# Маршрут для просмотра всех вопросов (административный)
@app.route('/admin/questions')
@admin_required  # Защищаем доступ
def admin_questions():
    """Страница просмотра всех вопросов (включая скрытые)"""
    questions = load_questions()

    # Логируем действие
    username = session.get('admin_username', 'Администратор')
    log_action(username, 'Просмотр списка вопросов в админке')

    return render_template('admin_questions.html',
                           questions=questions,
                           username=session.get('admin_username'))


# API для получения всех вопросов (административный)
@app.route('/admin/api/questions')
@admin_required
def admin_api_questions():
    """API для получения всех вопросов (включая скрытые)"""
    questions = load_questions()
    return jsonify(questions)





# Главная страница - тест
@app.route('/')
def index():
    """Главная страница приложения - страница теста"""
    # Логируем посещение главной страницы
    username = session.get('username', 'Гость')
    log_action(username, 'Посещение главной страницы теста')

    return render_template('index.html')


# Маршрут для получения вопросов
@app.route('/api/questions')
def get_questions():
    """API-метод для получения видимых вопросов теста"""
    questions = load_questions()
    # Возвращаем только видимые вопросы для обычных пользователей
    visible_questions = [q for q in questions if q.get('visible', True)]

    username = session.get('username', 'Гость')
    log_action(username, 'Запрос вопросов теста')

    return jsonify(visible_questions)


# Маршрут для отправки ответов
@app.route('/api/submit', methods=['POST'])
def submit_test():
    """API-метод для обработки результатов теста"""
    data = request.json
    username = data.get('username', 'Аноним')
    answers = data.get('answers', [])

    # Сохраняем имя пользователя в сессии
    session['username'] = username

    # Загружаем вопросы для проверки
    questions = load_questions()

    # Подсчет результатов
    score = 0
    results = []

    for answer in answers:
        question_id = answer['questionId']
        user_answer = answer['answer']

        # Находим вопрос
        question = next((q for q in questions if q['id'] == question_id), None)

        if question:
            is_correct = user_answer == question['correct']
            results.append({
                'questionId': question_id,
                'question': question['question'],
                'userAnswer': user_answer,
                'correctAnswer': question['correct'],
                'isCorrect': is_correct,
                'options': question['options']
            })

            if is_correct:
                score += 1

    # Сохраняем результаты
    save_results(username, results, score)

    # Логируем завершение теста
    log_action(username, f'Завершение теста. Результат: {score}/{len(results)}')

    return jsonify({
        'success': True,
        'username': username,
        'score': score,
        'total': len(results),
        'results': results
    })


# Маршрут для просмотра результатов
@app.route('/results')
def view_results():
    """Страница просмотра результатов тестирования"""
    username = session.get('username', 'Гость')
    log_action(username, 'Просмотр результатов теста')
    return render_template('results.html')


# API для получения всех результатов
@app.route('/api/results')
def get_results():
    """API-метод для получения всех результатов"""
    try:
        if os.path.exists(RESULTS_FILE):
            with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = []
    except:
        results = []

    return jsonify(results)

# Функция для сохранения вопросов
def save_questions(questions):
    """Сохранение вопросов в JSON файл"""
    with open(QUESTIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(questions, f, ensure_ascii=False, indent=2)


# Маршрут для удаления вопроса
@app.route('/admin/questions/delete/<int:question_id>')
@admin_required
def delete_question(question_id):
    """Удаление вопроса по ID"""
    questions = load_questions()

    # Находим индекс вопроса
    question_index = -1
    question_to_delete = None
    for i, q in enumerate(questions):
        if q['id'] == question_id:
            question_index = i
            question_to_delete = q
            break

    if question_index != -1:
        # Удаляем вопрос
        deleted_question = questions.pop(question_index)
        save_questions(questions)

        # Логируем удаление
        username = session.get('admin_username', 'Администратор')
        log_action(username, f'Удаление вопроса ID {question_id}: {deleted_question["question"][:50]}...')

        return jsonify({'success': True, 'message': 'Вопрос удален'})

    return jsonify({'success': False, 'message': 'Вопрос не найден'}), 404


# Маршрут для добавления вопроса (форма)
@app.route('/admin/questions/add')
@admin_required
def add_question_form():
    """Форма добавления нового вопроса"""
    return render_template('admin_add_question.html')


# Маршрут для обработки добавления вопроса
@app.route('/admin/questions/add', methods=['POST'])
@admin_required
def add_question():
    """Обработка добавления нового вопроса"""
    try:
        # Получаем данные из формы
        question_text = request.form.get('question', '').strip()
        options_text = request.form.get('options', '').strip()
        correct_answer = request.form.get('correct', '0').strip()
        visible = request.form.get('visible', 'true') == 'true'

        # Валидация
        if not question_text:
            return jsonify({'success': False, 'message': 'Введите текст вопроса'})

        if not options_text:
            return jsonify({'success': False, 'message': 'Введите варианты ответов'})

        # Разделяем варианты ответов по строкам
        options = [opt.strip() for opt in options_text.split('\n') if opt.strip()]

        if len(options) < 2:
            return jsonify({'success': False, 'message': 'Должно быть минимум 2 варианта ответа'})

        try:
            correct_index = int(correct_answer)
            if correct_index < 0 or correct_index >= len(options):
                return jsonify({'success': False, 'message': 'Номер правильного ответа вне диапазона'})
        except ValueError:
            return jsonify({'success': False, 'message': 'Некорректный номер правильного ответа'})

        # Загружаем существующие вопросы
        questions = load_questions()

        # Генерируем новый ID (максимальный существующий + 1)
        new_id = max([q['id'] for q in questions], default=0) + 1

        # Создаем новый вопрос
        new_question = {
            'id': new_id,
            'question': question_text,
            'options': options,
            'correct': correct_index,
            'visible': visible
        }

        # Добавляем вопрос в список
        questions.append(new_question)

        # Сохраняем обновленный список
        save_questions(questions)

        # Логируем добавление
        username = session.get('admin_username', 'Администратор')
        log_action(username, f'Добавление вопроса ID {new_id}: {question_text[:50]}...')

        return jsonify({
            'success': True,
            'message': 'Вопрос добавлен',
            'question_id': new_id
        })

    except Exception as e:
        return jsonify({'success': False, 'message': f'Ошибка: {str(e)}'}), 500


# Добавим в app.py (после функции add_question)

# Функция для сбора статистики
def get_statistics():
    """Сбор статистики по ответам на вопросы"""
    # Загружаем вопросы
    questions = load_questions()
    questions_dict = {q['id']: q for q in questions}

    # Загружаем результаты
    try:
        if os.path.exists(RESULTS_FILE):
            with open(RESULTS_FILE, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = []
    except:
        results = []

    # Инициализируем статистику для каждого вопроса
    stats = {}
    for q in questions:
        stats[q['id']] = {
            'id': q['id'],
            'question': q['question'],
            'visible': q['visible'],
            'total_attempts': 0,  # сколько раз на вопрос отвечали
            'correct_answers': 0,  # сколько правильных ответов
            'incorrect_answers': 0,  # сколько неправильных ответов
            'percentage': 0,  # процент правильных
            'options_stats': [0] * len(q['options'])  # сколько раз выбирали каждый вариант
        }

    # Обрабатываем все результаты
    for result in results:
        if 'answers' in result:
            for answer in result['answers']:
                question_id = answer['questionId']

                # Проверяем, есть ли такой вопрос в статистике
                if question_id in stats:
                    stats[question_id]['total_attempts'] += 1

                    # Проверяем правильность ответа
                    if answer.get('isCorrect', False):
                        stats[question_id]['correct_answers'] += 1
                    else:
                        stats[question_id]['incorrect_answers'] += 1

                    # Статистика по выбранному варианту
                    user_answer = answer.get('userAnswer')
                    if user_answer is not None and user_answer < len(stats[question_id]['options_stats']):
                        stats[question_id]['options_stats'][user_answer] += 1

    # Рассчитываем проценты для каждого вопроса
    for q_id in stats:
        if stats[q_id]['total_attempts'] > 0:
            percentage = (stats[q_id]['correct_answers'] / stats[q_id]['total_attempts']) * 100
            stats[q_id]['percentage'] = round(percentage, 1)

    # Преобразуем в список и сортируем по ID
    stats_list = list(stats.values())
    stats_list.sort(key=lambda x: x['id'])

    # Общая статистика
    total_stats = {
        'total_questions': len(questions),
        'visible_questions': sum(1 for q in questions if q['visible']),
        'total_tests_taken': len(results),
        'questions_with_answers': sum(1 for s in stats_list if s['total_attempts'] > 0),
        'average_correct_percentage': 0
    }

    # Рассчитываем средний процент правильных ответов
    questions_with_attempts = [s for s in stats_list if s['total_attempts'] > 0]
    if questions_with_attempts:
        avg_percentage = sum(s['percentage'] for s in questions_with_attempts) / len(questions_with_attempts)
        total_stats['average_correct_percentage'] = round(avg_percentage, 1)

    return stats_list, total_stats


# Маршрут для страницы статистики
@app.route('/admin/statistics')
@admin_required
def admin_statistics():
    """Страница статистики ответов на вопросы"""
    stats_list, total_stats = get_statistics()

    # Логируем просмотр статистики
    username = session.get('admin_username', 'Администратор')
    log_action(username, 'Просмотр статистики ответов')

    return render_template('admin_statistics.html',
                           stats=stats_list,
                           total_stats=total_stats,
                           username=username)


# Маршрут для просмотра логов действий
@app.route('/admin/logs')
@admin_required
def admin_logs():
    """Страница просмотра логов действий пользователей"""
    # Логируем сам факт просмотра логов
    username = session.get('admin_username', 'Администратор')
    log_action(username, 'Просмотр логов действий пользователей')

    # Загружаем логи
    logs = load_logs()

    return render_template('admin_logs.html',
                           logs=logs,
                           username=username,
                           total_logs=len(logs))


# Функция для загрузки логов
def load_logs():
    """Загрузка логов из JSON файла"""
    logs = []

    try:
        if os.path.exists('user_actions.json'):
            with open('user_actions.json', 'r', encoding='utf-8') as f:
                # Читаем все строки
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            logs.append(log_entry)
                        except json.JSONDecodeError:
                            # Пропускаем некорректные строки
                            continue
    except Exception as e:
        print(f"Ошибка загрузки логов: {e}")

    # Сортируем по дате и времени (новые сверху)
    logs.sort(key=lambda x: (x.get('date', ''), x.get('time', '')), reverse=True)

    return logs


# Маршрут для очистки логов
@app.route('/admin/logs/clear', methods=['POST'])
@admin_required
def clear_logs():
    """Очистка файла логов"""
    try:
        # Создаем пустой файл
        with open('user_actions.json', 'w', encoding='utf-8') as f:
            f.write('')

        # Логируем очистку
        username = session.get('admin_username', 'Администратор')
        log_action(username, 'Очистка файла логов')

        return jsonify({'success': True, 'message': 'Логи очищены'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Ошибка: {str(e)}'}), 500


# Маршрут для экспорта логов
@app.route('/admin/logs/export')
@admin_required
def export_logs():
    """Экспорт логов в CSV формате"""
    logs = load_logs()

    # Создаем CSV
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Заголовок
    writer.writerow(['Логи действий пользователей'])
    writer.writerow(['Дата экспорта:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow(['Всего записей:', len(logs)])
    writer.writerow([])

    # Заголовки таблицы
    writer.writerow(['Дата', 'Время', 'Пользователь', 'Действие'])

    # Данные
    for log in logs:
        writer.writerow([
            log.get('date', ''),
            log.get('time', ''),
            log.get('user', ''),
            log.get('action', '')
        ])

    # Логируем экспорт
    username = session.get('admin_username', 'Администратор')
    log_action(username, 'Экспорт логов в CSV')

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=user_logs.csv"}
    )


# API для получения логов (для AJAX загрузки)
@app.route('/admin/api/logs')
@admin_required
def api_logs():
    """API для получения логов в JSON формате"""
    logs = load_logs()

    # Поддерживаем фильтрацию через параметры запроса
    user_filter = request.args.get('user', '')
    action_filter = request.args.get('action', '')
    date_filter = request.args.get('date', '')

    filtered_logs = logs

    if user_filter:
        filtered_logs = [log for log in filtered_logs if user_filter.lower() in log.get('user', '').lower()]

    if action_filter:
        filtered_logs = [log for log in filtered_logs if action_filter.lower() in log.get('action', '').lower()]

    if date_filter:
        filtered_logs = [log for log in filtered_logs if log.get('date', '') == date_filter]

    return jsonify({
        'logs': filtered_logs,
        'total': len(filtered_logs),
        'filtered': len(filtered_logs) != len(logs)
    })


# API для получения статистики (JSON)
@app.route('/admin/api/statistics')
@admin_required
def api_statistics():
    """API для получения статистики в JSON формате"""
    stats_list, total_stats = get_statistics()
    return jsonify({
        'questions_stats': stats_list,
        'total_stats': total_stats
    })


# API для экспорта статистики в CSV
@app.route('/admin/statistics/export')
@admin_required
def export_statistics():
    """Экспорт статистики в CSV формат"""
    stats_list, total_stats = get_statistics()

    # Создаем CSV
    import csv
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # Заголовок
    writer.writerow(['Статистика ответов на вопросы'])
    writer.writerow(['Дата экспорта:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])

    # Общая статистика
    writer.writerow(['ОБЩАЯ СТАТИСТИКА'])
    writer.writerow(['Всего вопросов:', total_stats['total_questions']])
    writer.writerow(['Видимых вопросов:', total_stats['visible_questions']])
    writer.writerow(['Пройдено тестов:', total_stats['total_tests_taken']])
    writer.writerow(['Вопросов с ответами:', total_stats['questions_with_answers']])
    writer.writerow(['Средний % правильных:', f"{total_stats['average_correct_percentage']}%"])
    writer.writerow([])

    # Детальная статистика по вопросам
    writer.writerow(['ДЕТАЛЬНАЯ СТАТИСТИКА ПО ВОПРОСАМ'])
    writer.writerow(['ID', 'Вопрос', 'Всего ответов', 'Правильно', 'Неправильно', 'Процент правильных'])

    for stat in stats_list:
        writer.writerow([
            stat['id'],
            stat['question'],
            stat['total_attempts'],
            stat['correct_answers'],
            stat['incorrect_answers'],
            f"{stat['percentage']}%"
        ])

    # Логируем экспорт
    username = session.get('admin_username', 'Администратор')
    log_action(username, 'Экспорт статистики в CSV')

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=statistics.csv"}
    )

if __name__ == '__main__':
    # Создаем папки если их нет
    os.makedirs('data', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

    # Запускаем сервер в режиме отладки
    app.run(debug=True, port=5000)

