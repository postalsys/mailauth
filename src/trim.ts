// Trims the characters of `chars` off the end of a string with an index scan. A regex such
// as /[ \t]+$/ retries the trailing run from every position inside it whenever the run is
// not at the end of the string, quadratic in the length of a run of those characters
const trimEndChars = (str: string, chars: string): string => {
    let end = str.length;
    while (end > 0 && chars.includes(str[end - 1])) {
        end--;
    }
    return str.slice(0, end);
};

// Trims the characters of `chars` off both ends of a string, see trimEndChars
const trimChars = (str: string, chars: string): string => {
    let start = 0;
    let end = str.length;
    while (start < end && chars.includes(str[start])) {
        start++;
    }
    while (end > start && chars.includes(str[end - 1])) {
        end--;
    }
    return str.slice(start, end);
};

export { trimChars, trimEndChars };
