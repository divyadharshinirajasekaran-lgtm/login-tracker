document.addEventListener('DOMContentLoaded', function() {
  setTimeout(() => {
    document.querySelectorAll('.alert-dismissible').forEach(a => {
      new bootstrap.Alert(a).close();
    });
  }, 4000);
});
