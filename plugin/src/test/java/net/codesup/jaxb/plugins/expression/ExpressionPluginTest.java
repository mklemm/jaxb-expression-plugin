package net.codesup.jaxb.plugins.expression;

import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.sun.codemodel.JCodeModel;
import com.sun.codemodel.JExpression;

/**
 * @author Mirko Klemm 2016-05-20
 */
public class ExpressionPluginTest {
	@Test
	public void testFindNamespaceMappings() throws IOException, SAXException, ParserConfigurationException {
		final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		final DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		final Document doc = documentBuilder.parse(getClass().getResource("testdoc.xml").toString());
		final String testString = "xsl:concat(html:derive(), xmf:func(wbn:n)/ns2:sf/ns3:fd,lengthy-prefix:pfx";
		final JExpression expr = ExpressionPlugin.findNamespaceMappings(new JCodeModel(), testString, doc.getDocumentElement());
		Assert.assertNotNull(expr);
	}
}
