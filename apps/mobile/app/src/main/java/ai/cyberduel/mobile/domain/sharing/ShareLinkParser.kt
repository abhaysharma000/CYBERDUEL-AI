package ai.cyberduel.mobile.domain.sharing

import java.util.regex.Pattern

object ShareLinkParser {

    private const val MAX_URLS = 5
    private const val MAX_URL_LENGTH = 4096

    // Matches http://, https://, or www. links
    private val URL_REGEX = Pattern.compile(
        "(?:https?://|www\\.)[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{0,256}\\.[a-zA-Z0-9()]{1,6}\\b[-a-zA-Z0-9()@:%_+.~#?&/=]*",
        Pattern.CASE_INSENSITIVE
    )

    // Trailing punctuation that should not be part of the URL when extracted from text
    private val TRAILING_PUNCTUATION = charArrayOf('.', ',', ';', '!', '?', ')', ']', '}', '>', '\'', '"')

    fun extractUrls(text: String?): List<String> {
        if (text.isNullOrBlank()) return emptyList()

        val results = mutableListOf<String>()
        val matcher = URL_REGEX.matcher(text)

        while (matcher.find() && results.size < MAX_URLS) {
            var rawMatch = matcher.group().trim()

            // Strip trailing punctuation
            while (rawMatch.isNotEmpty() && rawMatch.last() in TRAILING_PUNCTUATION) {
                // If closing parenthesis is stripped, only strip if there are more closing than opening
                if (rawMatch.last() == ')') {
                    val openCount = rawMatch.count { it == '(' }
                    val closeCount = rawMatch.count { it == ')' }
                    if (closeCount > openCount) {
                        rawMatch = rawMatch.dropLast(1)
                    } else {
                        break
                    }
                } else {
                    rawMatch = rawMatch.dropLast(1)
                }
            }

            if (rawMatch.isNotEmpty() && rawMatch.length <= MAX_URL_LENGTH) {
                // Prepend https:// if starts with www.
                val formatted = if (rawMatch.startsWith("www.", ignoreCase = true)) {
                    "https://$rawMatch"
                } else {
                    rawMatch
                }

                if (!results.contains(formatted)) {
                    results.add(formatted)
                }
            }
        }

        return results
    }
}

