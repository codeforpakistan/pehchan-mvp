document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('loginForm');

    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        // Client-side validation
        if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
            alert('Invalid email address');
            return;
        }

        if (password.length < 8) {
            alert('Invalid password');
            return;
        }

        // Send data to server
        fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                email: email,
                password: password
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = data.redirect;
            } else {
                alert(data.message);
            }
        })
        .catch((error) => {
            console.error('Error:', error);
            alert('An error occurred. Please try again.');
        });
    });
});
