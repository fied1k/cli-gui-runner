function onRequest(req, res) {
    if (req.Method == "POST") {
        log("POST " + req.Hostname + req.Path +
            " | Body: " + req.ReadBody());
    }
}
