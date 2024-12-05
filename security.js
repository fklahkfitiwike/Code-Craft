// security.js

// Utility function to generate a secure random token
const generateToken = () => {
    const array = new Uint32Array(32);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

// Set a secure cookie with HttpOnly, Secure, and SameSite attributes
const setSecureCookie = (name, value, days) => {
    let expires = "";
    if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "") + expires + "; path=/; Secure; HttpOnly; SameSite=Strict";
};

// Get a secure cookie
const getSecureCookie = (name) => {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
};

// Erase a cookie
const eraseCookie = (name) => {
    document.cookie = name + '=; Max-Age=-99999999;';
};

// Input validation
const validateInput = (input, type) => {
    const regexPatterns = {
        username: /^[a-zA-Z0-9_]{3,20}$/,
        email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        password: /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/
    };
    return regexPatterns[type].test(input);
};

// Password encryption (SHA-256)
const hashPassword = async (password) => {
    const msgUint8 = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

// CSRF protection
const csrfToken = generateToken();
setSecureCookie('X-CSRF-TOKEN', csrfToken, 1);

// Secure form submission
const secureFormSubmission = async (formId, endpoint, method) => {
    document.getElementById(formId).addEventListener('submit', async function(event) {
        event.preventDefault();
        const formData = new FormData(event.target);
        const json = JSON.stringify(Object.fromEntries(formData));

        const response = await fetch(endpoint, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': getSecureCookie('X-CSRF-TOKEN')
            },
            body: json
        });

        const result = await response.json();
        console.log(result);
    });
};

// Rate limiting
let requestCount = 0;
const rateLimit = (maxRequests, timeWindow) => {
    const resetTime = setInterval(() => {
        requestCount = 0;
    }, timeWindow);

    return (req, res, next) => {
        requestCount++;
        if (requestCount > maxRequests) {
            res.status(429).send('Too many requests, please try again later.');
        } else {
            next();
        }
    };
};

// Event listeners for form submissions
document.getElementById('signUpForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (validateInput(username, 'username') && validateInput(email, 'email') && validateInput(password, 'password')) {
        const hashedPassword = await hashPassword(password);
        secureFormSubmission('signUpForm', '/api/signup', 'POST');
    } else {
        console.error('Invalid input');
    }
});

document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    if (validateInput(username, 'username') && validateInput(password, 'password')) {
        const hashedPassword = await hashPassword(password);
        secureFormSubmission('loginForm', '/api/login', 'POST');
    } else {
        console.error('Invalid input');
    }
});