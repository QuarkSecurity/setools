/*
 * Convert policy analysis results to XML.
 */

#include <xmlpol/resultsxml.h>

extern const XmlDocument create_xmlpol() 
{
	XmlDocument xmlDoc = new XmlDocument();
	XmlDeclaration xmlDeclaration = xmlDoc.CreateXmlDeclaration("1.0","utf-8",null); 
	XmlElement rootNode  = xmlDoc.CreateElement("Apol Analysis Report");
	xmlDoc.InsertBefore(xmlDeclaration, xmlDoc.DocumentElement); 
	xmlDoc.AppendChild(rootNode);

	return xmlDoc;
}

extern const XmlDocument domain_trans_result_to_xml(apol_domain_trans_result_t *result, XmlDocument xmlDoc) 
{
	if (!xmlDoc)
		xmlDoc = create_xmlpol();

	/* 
	 * First add the start, entrypoint, and end types to the document.
	 */
        XmlElement parentNode  = xmlDoc.CreateElement("Domain Trans Result");
	parentNode.SetAttribute("Start Type",);
	parentNode.SetAttribute("Entrypoint Type",);
	parentNode.SetAttribute("End Type",);
        xmlDoc.DocumentElement.PrependChild(parentNode);

	return xmlDoc;
}

extern const XmlDocument infoflow_result_to_xml(infoflow_result_t *result, XmlDocument xmlDoc) 
{
	if (!xmlDoc)
		xmlDoc = create_xmlpol();

	return xmlDoc;
}

extern const XmlDocument relabel_result_to_xml(relabel_result_t *result, XmlDocument xmlDoc) 
{
	if (xmlDoc)
		xmlDoc = create_xmlpol();	

	return xmlDoc;
}

extern const XmlDocument types_relation_result_to_xml(types_relation_result_t *result, XmlDocument xmlDoc) 
{
	if (!XmlDocument)
		xmlDoc = create_xmlpol(); 

	return XmlDocument;
}
