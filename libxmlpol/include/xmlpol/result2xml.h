/*
 * Policy conversion to xml.
 */

#include <libxml2>
#include <apol/domain-trans-analysis.h>
#include <apol/infoflow-analysis.h>
#include <apol/relabel-analysis.h>
#include <apol/types-relation-analysis.h>

extern const XMLDoc domain_trans_result_to_xml(domain_trans_result_t *result, XMLDoc doc);
extern const XMLDoc infoflow_result_to_xml(inflow_result_t *result, XMLDoc doc);
extern const XMLDoc relabel_result_to_xml(relabel_result_t *result, XMLDoc doc);
extern const XMLDoc types_relation_result_to_xml(types_relation_result_t *result, XMLDoc doc);
