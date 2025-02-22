const socket = io(); // Connect to the WebSocket server

// Get room code from the template
const roomCode = document.getElementById('room-code').value;
const username = document.getElementById('username').value;
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-btn');
const messagesContainer = document.getElementById('messages-container');

// Join the chat room
socket.emit('join', { room: roomCode });

// Send message when clicking the send button
sendButton.addEventListener('click', () => {
    sendMessage();
});

// Send message when pressing Enter
messageInput.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        sendMessage();
    }
});

function sendMessage() {
    const message = messageInput.value.trim();
    if (message) {
        socket.emit('send_message', { room: roomCode, message: message });
        messageInput.value = '';
    }
}

// Listen for incoming messages
socket.on('receive_message', (data) => {
    const messageElement = document.createElement('div');
    messageElement.classList.add('message');
    messageElement.innerHTML = `<strong>${data.username}:</strong> ${data.message}`;
    messagesContainer.appendChild(messageElement);
    messagesContainer.scrollTop = messagesContainer.scrollHeight; // Auto-scroll to latest message
});
