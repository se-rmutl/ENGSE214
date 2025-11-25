document.addEventListener('DOMContentLoaded', () => {
    const commentsContainer = document.getElementById('comments-container');
    const commentForm = document.getElementById('comment-form');
    const nameInput = document.getElementById('name-input');
    const commentInput = document.getElementById('comment-input');
    let localComments = [];

    function displayComments(comments) {
        commentsContainer.innerHTML = '';
        comments.forEach(comment => {
            const commentElement = document.createElement('div');
            commentElement.className = 'comment';
            // VULNERABILITY IS HERE!
            // การใช้ .innerHTML กับข้อมูลที่ผู้ใช้ป้อนเข้ามาโดยตรง
            // ทำให้เบราว์เซอร์รันโค้ดที่อาจเป็นอันตรายได้
            commentElement.innerHTML = `<strong>${comment.name}:</strong> ${comment.text}`;
            commentsContainer.appendChild(commentElement);
        });
    }

    async function fetchComments() {
        try {
            const response = await fetch('db.json');
            const data = await response.json();
            localComments = data.comments;
            displayComments(localComments);
        } catch (error) {
            console.error('Failed to fetch comments:', error);
            commentsContainer.textContent = 'ไม่สามารถโหลดความคิดเห็นได้';
        }
    }

    function handleFormSubmit(event) {
        event.preventDefault();
        const newComment = {
            id: Date.now(),
            name: nameInput.value,
            text: commentInput.value
        };
        localComments.push(newComment);
        displayComments(localComments);
        commentForm.reset();
    }

    commentForm.addEventListener('submit', handleFormSubmit);
    fetchComments();
});