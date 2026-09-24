// ==========================================
// PHISHING AWARENESS PROGRAM
// Interactive Quiz
// ==========================================


const questions = [

    {
        question:
            "You receive an email saying your account will be suspended in 10 minutes unless you click a link. What should you do?",

        answers: [
            "Click the link immediately",
            "Reply with your password",
            "Verify the message through the organization's official website or app",
            "Forward the email to your contacts"
        ],

        correct: 2
    },


    {
        question:
            "Which is a common warning sign of a phishing email?",

        answers: [
            "An expected message from a known contact",
            "An unexpected request for sensitive information",
            "A normal company newsletter",
            "A calendar reminder you created"
        ],

        correct: 1
    },


    {
        question:
            "What should you check before entering credentials on a website?",

        answers: [
            "The number of images on the page",
            "The website URL and domain",
            "The color of the login button",
            "The number of advertisements"
        ],

        correct: 1
    },


    {
        question:
            "What is social engineering?",

        answers: [
            "A method of repairing computer hardware",
            "A technique that manipulates people into performing unsafe actions",
            "A type of database",
            "A network routing protocol"
        ],

        correct: 1
    },


    {
        question:
            "Which practice provides additional protection if a password is stolen?",

        answers: [
            "Using the same password everywhere",
            "Disabling security notifications",
            "Multi-factor authentication",
            "Sharing the password with a colleague"
        ],

        correct: 2
    }

];


let currentQuestion = 0;

let score = 0;

let answered = false;


// ==========================================
// Load Question
// ==========================================

function loadQuestion() {

    const questionData = questions[currentQuestion];

    document.getElementById(
        "question-number"
    ).textContent = currentQuestion + 1;


    document.getElementById(
        "question"
    ).textContent = questionData.question;


    const answersContainer =
        document.getElementById("answers");


    answersContainer.innerHTML = "";

    answered = false;


    questionData.answers.forEach(
        (answer, index) => {

            const button =
                document.createElement("button");


            button.className = "answer";

            button.textContent = answer;


            button.addEventListener(
                "click",
                () => selectAnswer(index)
            );


            answersContainer.appendChild(button);
        }
    );


    const nextButton =
        document.getElementById("next-button");


    nextButton.disabled = false;

    nextButton.textContent =
        currentQuestion === questions.length - 1
            ? "Finish Quiz"
            : "Next Question";
}


// ==========================================
// Select Answer
// ==========================================

function selectAnswer(selectedIndex) {

    if (answered) {
        return;
    }


    answered = true;


    const correctIndex =
        questions[currentQuestion].correct;


    const answerButtons =
        document.querySelectorAll(".answer");


    answerButtons.forEach(
        (button, index) => {

            button.disabled = true;


            if (index === correctIndex) {

                button.classList.add("correct");

            }


            if (
                index === selectedIndex &&
                selectedIndex !== correctIndex
            ) {

                button.classList.add("wrong");

            }

        }
    );


    if (selectedIndex === correctIndex) {

        score++;

    }
}


// ==========================================
// Next Question
// ==========================================

function nextQuestion() {

    if (!answered) {

        alert(
            "Please select an answer before continuing."
        );

        return;
    }


    currentQuestion++;


    if (currentQuestion < questions.length) {

        loadQuestion();

    } else {

        showResult();

    }
}


// ==========================================
// Show Result
// ==========================================

function showResult() {

    document.getElementById(
        "quiz-question"
    ).classList.add("hidden");


    document.getElementById(
        "quiz-result"
    ).classList.remove("hidden");


    document.getElementById(
        "score"
    ).textContent =
        `${score} / ${questions.length}`;


    const percentage =
        (score / questions.length) * 100;


    let message;


    if (percentage === 100) {

        message =
            "Excellent! You have a strong understanding of phishing awareness.";

    } else if (percentage >= 80) {

        message =
            "Great job! You understand most phishing warning signs.";

    } else if (percentage >= 60) {

        message =
            "Good effort. Review the warning signs and security tips.";

    } else {

        message =
            "Keep learning. Review the training material and try again.";

    }


    document.getElementById(
        "result-message"
    ).textContent = message;
}


// ==========================================
// Restart Quiz
// ==========================================

function restartQuiz() {

    currentQuestion = 0;

    score = 0;

    document.getElementById(
        "quiz-result"
    ).classList.add("hidden");


    document.getElementById(
        "quiz-question"
    ).classList.remove("hidden");


    loadQuestion();


    document.getElementById(
        "quiz"
    ).scrollIntoView({
        behavior: "smooth"
    });
}


// ==========================================
// Start Quiz
// ==========================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadQuestion();

    }
);