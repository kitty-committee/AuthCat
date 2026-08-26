#include "lexbor/core/base.h"
#include "lexbor/dom/exception.h"
#include "lexbor/dom/interfaces/node.h"
#include <AuthCat/html.hpp>
#include <AuthCat/oauth.hpp>
#include <cstring>
using namespace nathcat::html;

bool __ended_at_replacement = false;

lexbor_action_t __dom_tree_template_walker(lxb_dom_node_t *node, void *ctx) {

  if (node->type == LXB_DOM_NODE_TYPE_ELEMENT) { // If the node is an element...
    // Check whether or not it has the template attribute
    lxb_dom_attr_t *firstAttr =
        lxb_dom_element_first_attribute((lxb_dom_element_t *)node);
    if (firstAttr != nullptr) {
      // Get the element and first attribute names
      size_t eLen, aLen;
      const lxb_char_t *pElementName =
          lxb_dom_element_local_name(firstAttr->owner, &eLen);
      const lxb_char_t *pAttrName = lxb_dom_attr_local_name(firstAttr, &aLen);

      std::string elementName((char *)pElementName, eLen);
      std::string attrName((char *)pAttrName, aLen);

      if (attrName.compare(AUTHCAT_TEMPLATE_ATTR_NAME) == 0) {
        std::string templateContent =
            nathcat::auth::util::read_file(std::string(AUTHCAT_TEMPLATES_DIR)
                                               .append(elementName)
                                               .append(".html"));

        // Parse the template content
        lxb_html_document_t *doc = lxb_html_document_create();
        if (doc == NULL)
          throw FailedToCreateDocument();

        const lxb_char_t *pTemplateContent =
            (lxb_char_t *)templateContent.c_str();
        lxb_status_t status = lxb_html_document_parse(doc, pTemplateContent,
                                                      templateContent.size());
        if (status != LXB_STATUS_OK) {
          lxb_html_document_destroy(doc);
          throw FailedToParseDocument();
        }

        // ... and then replace the node with the template
        lxb_dom_exception_code_t ex = lxb_dom_node_replace_child(
            node->parent, lxb_dom_interface_node(doc->body), node);

        if (ex != LXB_DOM_EXCEPTION_OK) {
          lxb_html_document_destroy(doc);
          throw FailedToInsertTemplate();
        }

        __ended_at_replacement = true;
        return LEXBOR_ACTION_STOP;
      }
    }
  }

  __ended_at_replacement = false;
  return LEXBOR_ACTION_OK;
}

std::string nathcat::html::parse_templated_html(std::string rootHtmlFile) {
  // Create and parse the specified document
  lxb_html_document_t *doc = lxb_html_document_create();

  if (doc == NULL) {
    throw FailedToCreateDocument();
  }

  std::string html = nathcat::auth::util::read_file(rootHtmlFile);

  const lxb_char_t *pHtml = (lxb_char_t *)html.c_str();

  lxb_status_t status = lxb_html_document_parse(doc, pHtml, html.size());
  if (status != LXB_STATUS_OK) {
    lxb_html_document_destroy(doc);
    throw FailedToParseDocument();
  }

  // Find all nodes with the template attribute as their first attribute
  do {
    lxb_dom_node_simple_walk(lxb_dom_interface_node(doc->body),
                             __dom_tree_template_walker, NULL);
  } while (__ended_at_replacement);

  // Serialize the document into a string
  lexbor_str_t str = {0};
  lxb_html_serialize_deep_str(lxb_dom_interface_node(doc), &str);
  std::string finalContent((char *)str.data, str.length);

  lxb_html_document_destroy(doc);
  return finalContent;
}
