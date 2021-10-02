$('nav').click(function(e){
    e.preventDefault();
    $('body, html').animate({
        scrollTop: $( $(this).attr('href') ).offset().top - 120
    }, 1000);
});