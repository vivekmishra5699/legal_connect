// static/js/script.js
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Character counter for textareas
    const textareas = document.querySelectorAll('textarea[maxlength]');
    textareas.forEach(textarea => {
        const counter = document.createElement('div');
        counter.className = 'form-text text-muted text-end';
        counter.innerHTML = `0/${textarea.maxLength} characters`;
        textarea.parentNode.appendChild(counter);

        textarea.addEventListener('input', function() {
            counter.innerHTML = `${this.value.length}/${this.maxLength} characters`;
        });
    });

    // Tags input enhancement
    const tagsInput = document.getElementById('tags');
    if (tagsInput) {
        tagsInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                const value = this.value.trim();
                if (value && !value.endsWith(',')) {
                    this.value = value + ', ';
                }
            }
        });
    }
    
    // Handle category selection in question filters
    const categorySelect = document.getElementById('category');
    if (categorySelect) {
        categorySelect.addEventListener('change', function() {
            // If this is on the browse page and not part of a form submission
            if (window.location.pathname.includes('/questions') && !this.closest('form').getAttribute('method')) {
                const searchParams = new URLSearchParams(window.location.search);
                searchParams.set('category', this.value);
                window.location.href = `${window.location.pathname}?${searchParams.toString()}`;
            }
        });
    }

    // Confirm actions
    const confirmBtns = document.querySelectorAll('[data-confirm]');
    confirmBtns.forEach(btn => {
        btn.addEventListener('click', function(e) {
            if (!confirm(this.getAttribute('data-confirm'))) {
                e.preventDefault();
            }
        });
    });
    
    // Auto-expand textareas
    const autoExpandTextareas = document.querySelectorAll('textarea.auto-expand');
    autoExpandTextareas.forEach(textarea => {
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
        
        // Initial height set
        textarea.dispatchEvent(new Event('input'));
    });
    
    // Highlight code blocks if Prism.js is available
    if (typeof Prism !== 'undefined') {
        Prism.highlightAll();
    }
});

// Mark notifications as read when clicked
function markNotificationAsRead(notificationId) {
    fetch(`/notifications/${notificationId}/read`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => {
        if (response.ok) {
            const notificationElement = document.getElementById(`notification-${notificationId}`);
            if (notificationElement) {
                notificationElement.classList.remove('unread');
                notificationElement.classList.add('read');
            }
        }
    });
}

// Preview question content as you type
function previewContent() {
    const content = document.getElementById('content').value;
    const previewElement = document.getElementById('content-preview');
    
    if (previewElement) {
        // Basic Markdown-like conversion
        let previewContent = content
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/\n/g, '<br>');
            
        previewElement.innerHTML = previewContent;
    }
}