document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('registerForm');

    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const fullName = document.getElementById('fullName').value;
        const email = document.getElementById('email').value;
        const phone = document.getElementById('phone').value;
        const cnic = document.getElementById('cnic').value;
        const password = document.getElementById('password').value;

        // Client-side validation
        if (!/^[A-Za-z\s]+$/.test(fullName)) {
            alert('Invalid full name');
            return;
        }

        if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
            alert('Invalid email address');
            return;
        }

        if (!/^\d{11}$/.test(phone)) {
            alert('Invalid phone number (must be 11 digits)');
            return;
        }

        if (!/^\d{13}$/.test(cnic)) {
            alert('Invalid CNIC (must be 13 digits)');
            return;
        }

        if (password.length < 8) {
            alert('Password must be at least 8 characters long');
            return;
        }

        // Send data to server
        fetch('/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                fullName: fullName,
                email: email,
                phone: phone,
                cnic: cnic,
                password: password
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(data.message);
                window.location.href = '/login';
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
