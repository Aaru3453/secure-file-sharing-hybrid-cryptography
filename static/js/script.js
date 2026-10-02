/**
 * Secure File Sharing System Using Hybrid Cryptography
 * Frontend UX and Interactive Enhancements
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Drag-and-drop file upload handler
    const dropzone = document.querySelector('.file-dropzone');
    const fileInput = document.querySelector('#fileInput');
    const fileDetails = document.querySelector('#selectedFileDetails');
    const fileNameSpan = document.querySelector('#selectedFileName');
    const fileSizeSpan = document.querySelector('#selectedFileSize');

    if (dropzone && fileInput) {
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('dragover');
            });
        });

        dropzone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileInfo(files[0]);
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                updateFileInfo(fileInput.files[0]);
            }
        });
    }

    function updateFileInfo(file) {
        if (fileDetails && fileNameSpan && fileSizeSpan) {
            fileNameSpan.textContent = file.name;
            fileSizeSpan.textContent = formatBytes(file.size);
            fileDetails.style.display = 'block';
        }
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    // 2. Registration RSA Key Generation Visual Spinner
    const regForm = document.querySelector('#registerForm');
    const regBtn = document.querySelector('#registerSubmitBtn');
    const regSpinner = document.querySelector('#registerKeygenNotice');

    if (regForm && regBtn) {
        regForm.addEventListener('submit', () => {
            regBtn.disabled = true;
            regBtn.innerHTML = 'Generating RSA-2048 Keys...';
            if (regSpinner) {
                regSpinner.style.display = 'flex';
            }
        });
    }

    // 3. Copy to clipboard helper
    document.querySelectorAll('.copy-btn').forEach(button => {
        button.addEventListener('click', () => {
            const textToCopy = button.getAttribute('data-copy');
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalText = button.innerHTML;
                    button.innerHTML = '✓ Copied!';
                    setTimeout(() => {
                        button.innerHTML = originalText;
                    }, 2000);
                });
            }
        });
    });

    // 4. Auto dismiss flash alerts after 5 seconds
    setTimeout(() => {
        document.querySelectorAll('.flash-alert').forEach(alert => {
            alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            setTimeout(() => alert.remove(), 500);
        });
    }, 5000);
});
