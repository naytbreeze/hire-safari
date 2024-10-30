// Declare BookingWidget as a global variable
window.BookingWidget = function() {
    // Hook declarations
    const [selectedDate, setSelectedDate] = React.useState('');
    const [availableSlots, setAvailableSlots] = React.useState([]);
    const [selectedTime, setSelectedTime] = React.useState('');
    const [phoneNumber, setPhoneNumber] = React.useState('');  // New state for phone
    const [isLoading, setIsLoading] = React.useState(false);
    const [message, setMessage] = React.useState('');

    // Get CSRF token from meta tag
    const getCsrfToken = () => {
        const token = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        return token;
    };

    // Convert 24h to 12h format
    const formatTime = (time) => {
        const [hours, minutes] = time.split(':');
        const hour = parseInt(hours);
        const ampm = hour >= 12 ? 'PM' : 'AM';
        const formattedHour = hour % 12 || 12;
        return `${formattedHour}:${minutes} ${ampm}`;
    };

    // Phone number validation
    const isValidPhone = (phone) => {
        const cleaned = phone.replace(/\D/g, '');
        return cleaned.length === 10;
    };

    // Format phone number as user types
    const formatPhoneNumber = (value) => {
        const cleaned = value.replace(/\D/g, '');
        if (cleaned.length === 0) return '';
        if (cleaned.length <= 3) return cleaned;
        if (cleaned.length <= 6) return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3)}`;
        return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6, 10)}`;
    };

    // Fetch available slots when date changes
    React.useEffect(() => {
        if (selectedDate) {
            setIsLoading(true);
            fetch(`/book-listing/${window.LISTING_ID}/available-slots?date=${selectedDate}`, {
                method: 'GET',
                headers: {
                    'X-CSRF-TOKEN': getCsrfToken()
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    setMessage(data.error);
                    setAvailableSlots([]);
                } else {
                    setAvailableSlots(data.slots || []);
                    if (data.slots && data.slots.length === 0) {
                        setMessage('No available slots for this date');
                    } else {
                        setMessage('');
                    }
                }
            })
            .catch(error => {
                console.error('Error fetching slots:', error);
                setMessage('Error loading available times');
            })
            .finally(() => {
                setIsLoading(false);
            });
        }
    }, [selectedDate]);

    const handleBooking = () => {
        if (!selectedDate || !selectedTime) {
            setMessage('Please select both date and time');
            return;
        }

        if (!phoneNumber || !isValidPhone(phoneNumber)) {
            setMessage('Please enter a valid phone number');
            return;
        }

        setIsLoading(true);
        fetch(`/book-listing/${window.LISTING_ID}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': getCsrfToken()
            },
            body: JSON.stringify({
                date: selectedDate,
                time: selectedTime,
                phone: phoneNumber.replace(/\D/g, '')  // Send only digits
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                setMessage(data.error);
            } else {
                setMessage('Booking confirmed successfully!');
                setSelectedDate('');
                setSelectedTime('');
                setPhoneNumber('');
                setTimeout(() => window.location.reload(), 2000);
            }
        })
        .catch(error => {
            console.error('Error booking appointment:', error);
            setMessage('Error booking appointment');
        })
        .finally(() => {
            setIsLoading(false);
        });
    };

    // Render component
    return React.createElement(
        'div',
        { className: 'space-y-4' },
        // Date Selector
        React.createElement('div', { className: 'flex flex-col space-y-2' },
            React.createElement('label', { className: 'text-sm font-medium text-gray-700' }, 'Select Date'),
            React.createElement('input', {
                type: 'date',
                className: 'border rounded-lg px-3 py-2 w-full',
                value: selectedDate,
                onChange: (e) => setSelectedDate(e.target.value),
                min: new Date().toISOString().split('T')[0]
            })
        ),

        // Phone Number Input (new)
        React.createElement('div', { className: 'flex flex-col space-y-2' },
            React.createElement('label', { className: 'text-sm font-medium text-gray-700' }, 'Phone Number'),
            React.createElement('input', {
                type: 'tel',
                className: 'border rounded-lg px-3 py-2 w-full',
                value: phoneNumber,
                onChange: (e) => setPhoneNumber(formatPhoneNumber(e.target.value)),
                placeholder: '(XXX) XXX-XXXX',
                maxLength: 14
            })
        ),

        // Time Slots
        isLoading ? React.createElement('div', { className: 'text-center py-4' }, 'Loading available times...') :
        selectedDate && availableSlots.length > 0 ? React.createElement(
            'div',
            { className: 'grid grid-cols-3 gap-2' },
            availableSlots.map(slot => React.createElement(
                'button',
                {
                    key: slot,
                    className: `px-4 py-2 rounded-lg text-sm ${
                        selectedTime === slot
                            ? 'bg-blue-600 text-white'
                            : 'bg-gray-100 hover:bg-gray-200 text-gray-800'
                    }`,
                    onClick: () => setSelectedTime(slot)
                },
                formatTime(slot)
            ))
        ) : selectedDate ? React.createElement(
            'div',
            { className: 'text-center py-4 text-gray-500' },
            'No available slots for this date'
        ) : null,

        // Message Display
        message && React.createElement(
            'div',
            {
                className: `p-3 rounded-lg ${
                    message.includes('Error') ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                }`
            },
            message
        ),

        // Book Button
        React.createElement(
            'button',
            {
                className: `w-full py-3 rounded-lg text-white ${
                    selectedDate && selectedTime && isValidPhone(phoneNumber)
                        ? 'bg-blue-600 hover:bg-blue-700'
                        : 'bg-gray-300 cursor-not-allowed'
                }`,
                onClick: handleBooking,
                disabled: !selectedDate || !selectedTime || !isValidPhone(phoneNumber) || isLoading
            },
            isLoading ? 'Processing...' : 'Book Appointment'
        )
    );
};