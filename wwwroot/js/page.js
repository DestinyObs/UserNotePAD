//const pageLimit = 1000; // Adjust this to your desired character/word limit
//let currentPage = document.querySelector('.page');

//function createNewPage() {
//    const newPage = document.createElement('div');
//    newPage.classList.add('page');
//    newPage.contentEditable = true;
//    document.getElementById('container').appendChild(newPage);
//    currentPage = newPage;
//}

//function checkPageLimit() {
//    const text = currentPage.innerText || currentPage.textContent;
//    if (text.length >= pageLimit) {
//        createNewPage();
//    }
//}

//// Listen for input events (e.g., typing)
//currentPage.addEventListener('input', checkPageLimit);

// Function to load note content
function loadNoteContent(noteId) {
    $.ajax({
        url: '/Notes/GetNoteContent/' + noteId, // Replace with your controller action URL
        type: 'GET',
        success: function (data) {
            // Replace the content of the .page element with the retrieved content
            $('.page').html(data);
        },
        error: function (error) {
            console.error('Error loading note content: ' + error.responseText);
        }
    });
}

// Attach a click event handler to your note links in the navigation menu
$('.note-link').on('click', function (e) {
    e.preventDefault();
    var noteId = $(this).data('note-id'); // Get the note ID from data attribute
    loadNoteContent(noteId);
});