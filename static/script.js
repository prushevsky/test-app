// static/script.js
/**
 * Основной JavaScript файл для управления тестом
 * Этот код реализует клиентскую логику прохождения теста
 */

// Глобальные переменные для управления тестом
let questions = [];          // Массив вопросов
let currentQuestion = 0;     // Текущий вопрос
let userAnswers = {};        // Ответы пользователя
let username = '';           // Имя пользователя

// Функция для отображения ошибок
function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

// Функция начала теста
function startTest() {
    username = document.getElementById('username').value.trim();

    if (!username) {
        showError('Пожалуйста, введите ваше имя');
        return;
    }

    if (username.length < 2) {
        showError('Имя должно содержать минимум 2 символа');
        return;
    }

    // Показываем загрузку
    document.getElementById('usernameSection').style.display = 'none';
    document.getElementById('loading').style.display = 'block';

    // Загружаем вопросы с сервера
    loadQuestions();
}

// Функция загрузки вопросов
function loadQuestions() {
    fetch('/api/questions')
        .then(response => {
            if (!response.ok) {
                throw new Error('Ошибка загрузки вопросов');
            }
            return response.json();
        })
        .then(data => {
            questions = data;
            if (questions.length === 0) {
                showError('Вопросы не найдены');
                return;
            }

            // Инициализируем объект для ответов
            questions.forEach(q => {
                userAnswers[q.id] = null;
            });

            // Скрываем загрузку и показываем вопросы
            document.getElementById('loading').style.display = 'none';
            document.getElementById('progressBar').style.display = 'block';
            document.getElementById('questionsContainer').style.display = 'block';

            // Отображаем первый вопрос
            displayQuestion(currentQuestion);
            updateProgress();
        })
        .catch(error => {
            showError('Ошибка при загрузке вопросов: ' + error.message);
            document.getElementById('loading').style.display = 'none';
            document.getElementById('usernameSection').style.display = 'block';
        });
}

// Функция отображения вопроса
function displayQuestion(index) {
    if (index < 0 || index >= questions.length) {
        return;
    }

    const question = questions[index];
    const questionsList = document.getElementById('questionsList');

    // Создаем HTML для вопроса
    let html = `
        <div class="question" data-question-id="${question.id}">
            <h3>Вопрос ${index + 1} из ${questions.length}: ${question.question}</h3>
            <div class="options">
    `;

    // Добавляем варианты ответов
    question.options.forEach((option, optionIndex) => {
        const isSelected = userAnswers[question.id] === optionIndex;
        html += `
            <div class="option ${isSelected ? 'selected' : ''}"
                 onclick="selectOption(${question.id}, ${optionIndex})">
                ${String.fromCharCode(65 + optionIndex)}. ${option}
            </div>
        `;
    });

    html += '</div></div>';

    questionsList.innerHTML = html;

    // Обновляем кнопки навигации
    updateNavigationButtons();
}

// Функция выбора варианта ответа
function selectOption(questionId, optionIndex) {
    // Сохраняем ответ
    userAnswers[questionId] = optionIndex;

    // Обновляем визуальное состояние всех вариантов для этого вопроса
    const questionDiv = document.querySelector(`[data-question-id="${questionId}"]`);
    const options = questionDiv.querySelectorAll('.option');

    options.forEach((option, index) => {
        if (index === optionIndex) {
            option.classList.add('selected');
        } else {
            option.classList.remove('selected');
        }
    });

    // Автоматически переходим к следующему вопросу через 0.5 секунды
    setTimeout(() => {
        if (currentQuestion < questions.length - 1) {
            nextQuestion();
        }
    }, 500);
}

// Функция обновления кнопок навигации
function updateNavigationButtons() {
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const submitBtn = document.getElementById('submitBtn');

    // Кнопка "Назад"
    if (currentQuestion > 0) {
        prevBtn.style.display = 'inline-block';
    } else {
        prevBtn.style.display = 'none';
    }

    // Кнопки "Следующий" и "Завершить"
    if (currentQuestion < questions.length - 1) {
        nextBtn.style.display = 'inline-block';
        submitBtn.style.display = 'none';
    } else {
        nextBtn.style.display = 'none';
        submitBtn.style.display = 'inline-block';
    }
}

// Функция обновления прогресс-бара
function updateProgress() {
    const progress = document.getElementById('progress');
    const answeredQuestions = Object.values(userAnswers).filter(v => v !== null).length;
    const percentage = (answeredQuestions / questions.length) * 100;

    progress.style.width = percentage + '%';
}

// Функция перехода к следующему вопросу
function nextQuestion() {
    if (currentQuestion < questions.length - 1) {
        currentQuestion++;
        displayQuestion(currentQuestion);
        updateProgress();
    }
}

// Функция перехода к предыдущему вопросу
function prevQuestion() {
    if (currentQuestion > 0) {
        currentQuestion--;
        displayQuestion(currentQuestion);
        updateProgress();
    }
}

// Функция отправки теста
function submitTest() {
    // Проверяем, ответил ли пользователь на все вопросы
    const unansweredQuestions = Object.values(userAnswers).filter(v => v === null).length;

    if (unansweredQuestions > 0) {
        const confirmSubmit = confirm(`Вы ответили не на все вопросы (осталось ${unansweredQuestions}). Вы уверены, что хотите завершить тест?`);
        if (!confirmSubmit) {
            return;
        }
    }

    // Подготавливаем данные для отправки
    const answers = [];
    for (const [questionId, answer] of Object.entries(userAnswers)) {
        answers.push({
            questionId: parseInt(questionId),
            answer: answer
        });
    }

    const data = {
        username: username,
        answers: answers
    };

    // Отправляем данные на сервер
    fetch('/api/submit', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(result => {
        if (result.success) {
            // Показываем сообщение об успехе
            document.getElementById('questionsContainer').style.display = 'none';
            document.getElementById('progressBar').style.display = 'none';
            document.getElementById('successMessage').style.display = 'block';

            // Сохраняем результаты в localStorage для просмотра на странице результатов
            localStorage.setItem('lastTestResult', JSON.stringify(result));
        } else {
            showError('Ошибка при отправке ответов');
        }
    })
    .catch(error => {
        showError('Ошибка соединения с сервером: ' + error.message);
    });
}

// Функция для отладки - отображение текущего состояния
function debugState() {
    console.log('Текущий вопрос:', currentQuestion);
    console.log('Ответы пользователя:', userAnswers);
    console.log('Имя пользователя:', username);
    console.log('Всего вопросов:', questions.length);

    // Отображаем в alert для удобства отладки
    alert(`Отладочная информация:
Текущий вопрос: ${currentQuestion + 1}
Ответов дано: ${Object.values(userAnswers).filter(v => v !== null).length}
Имя: ${username}`);
}

// Добавляем обработчик для Enter в поле имени
document.getElementById('username').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        startTest();
    }
});

// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    // Можно добавить дополнительные действия при загрузке
    console.log('Страница теста загружена. Готов к работе.');

    // Для отладки: добавляем горячую клавишу Ctrl+D для отладки
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey && e.key === 'd') {
            e.preventDefault();
            debugState();
        }
    });
});