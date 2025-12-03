// Validation functions and database query sanitization

// Validate string length
function validateStringLength(str, min, max) {
    if (str.length < min || str.length > max) {
        return false;
    }
    return true;
}

// Validate if input is a number
function validateNumber(input) {
    return typeof input === 'number' && !isNaN(input);
}

// Sanitize a string for SQL queries
function sanitizeSQLString(str) {
    // Replace single quotes with double single quotes
    return str.replace(/'/g, "''");
}

module.exports = {
    validateStringLength,
    validateNumber,
    sanitizeSQLString,
};
