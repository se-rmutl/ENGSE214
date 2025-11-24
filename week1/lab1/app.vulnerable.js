document.addEventListener('DOMContentLoaded', () => {
    const commentsContainer = document.getElementById('comments-container');
    const commentForm = document.getElementById('comment-form');
    const nameInput = document.getElementById('name-input');
    const commentInput = document.getElementById('comment-input');

    // **การเปลี่ยนแปลงที่ 1: นำข้อมูลมาใส่ในโค้ดโดยตรง**
    // ไม่ต้องใช้ fetch('db.json') อีกต่อไป
    let localComments = [
        { "id": 1, "name": "Alice", "text": "นี่คือคอมเมนต์แรก!" },
        { "id": 2, "name": "Bob", "text": "เว็บนี้ใช้งานง่ายดีนะ" }
    ];


    function displayComments() {
        commentsContainer.innerHTML = '';
        localComments.forEach(comment => {
            const commentElement = document.createElement('div');
            commentElement.className = 'comment';
            
            // **จุดที่มีช่องโหว่ (VULNERABILITY)**
            // การใช้ .innerHTML กับข้อมูลที่ผู้ใช้ป้อนเข้ามาโดยตรง
            commentElement.innerHTML = `<strong>${comment.name}:</strong> ${comment.text}`;
            
            commentsContainer.appendChild(commentElement);
        });
    }

    function handleFormSubmit(event) {
        event.preventDefault();
        const newComment = {
            id: Date.now(),
            name: nameInput.value,
            text: commentInput.value
        };
        localComments.push(newComment);
        displayComments(); // อัปเดตการแสดงผล
        commentForm.reset();
    }

    // เริ่มการทำงาน
    commentForm.addEventListener('submit', handleFormSubmit);
    displayComments(); // แสดงคอมเมนต์เริ่มต้น
});