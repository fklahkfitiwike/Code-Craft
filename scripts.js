// scripts.js
document.addEventListener("DOMContentLoaded", function() {
    const sections = document.querySelectorAll('.language-section');
    sections.forEach(section => section.style.display = 'none'); // Hide all sections initially

    window.showLanguages = function(id) {
        sections.forEach(section => section.style.display = 'none'); // Hide all sections
        document.getElementById(id).style.display = 'block'; // Show the selected section
    };
});
document.getElementById("nameForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const name = document.getElementById("name").value;

    try {
        const response = await fetch("http://localhost:5000/api/Home/submit-name", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ name }),
        });

        const data = await response.json();
        if (response.ok) {
            document.getElementById("response").innerText = data.message;
        } else {
            document.getElementById("response").innerText = data;
        }
    } catch (error) {
        console.error("Error:", error);
    }
});