/**
 * @file html.hpp
 */
#ifndef HTML_HPP
#define HTML_HPP

#include <exception>
#include <lexbor/html/html.h>
#include <string>

#define AUTHCAT_HTML_ROOT "Assets/html/"
#define AUTHCAT_TEMPLATES_DIR "Assets/html/templates/"
#define AUTHCAT_TEMPLATE_ATTR_NAME "template"

namespace nathcat {
namespace html {
class FailedToCreateDocument : public std::exception {};
class FailedToParseDocument : public std::exception {};
class FailedToInsertTemplate : public std::exception {};

/**
 * @brief Parse a HTML file and replace all template nodes with their HTML
 * content.
 *
 * @param rootHtmlFile The root HTML file
 */
std::string parse_templated_html(std::string rootHtmlFile);
} // namespace html
} // namespace nathcat

#endif
