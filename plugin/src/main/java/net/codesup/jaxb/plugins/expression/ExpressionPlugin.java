/*
 * MIT License
 *
 * Copyright (c) 2014 Klemm Software Consulting, Mirko Klemm
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package net.codesup.jaxb.plugins.expression;

import java.io.StringWriter;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.Binder;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import com.kscs.util.plugins.xjc.base.AbstractPlugin;
import com.sun.codemodel.JArray;
import com.sun.codemodel.JClass;
import com.sun.codemodel.JCodeModel;
import com.sun.codemodel.JDefinedClass;
import com.sun.codemodel.JExpr;
import com.sun.codemodel.JExpression;
import com.sun.codemodel.JFieldVar;
import com.sun.codemodel.JInvocation;
import com.sun.codemodel.JMethod;
import com.sun.codemodel.JMod;
import com.sun.codemodel.JType;
import com.sun.tools.xjc.Options;
import com.sun.tools.xjc.model.Aspect;
import com.sun.tools.xjc.model.CBuiltinLeafInfo;
import com.sun.tools.xjc.model.CClassInfo;
import com.sun.tools.xjc.model.CCustomizable;
import com.sun.tools.xjc.model.CEnumLeafInfo;
import com.sun.tools.xjc.model.CPluginCustomization;
import com.sun.tools.xjc.outline.ClassOutline;
import com.sun.tools.xjc.outline.Outline;
import com.sun.xml.bind.v2.model.core.MaybeElement;

/**
 * XJC plugin to generate a "toString"-like method by generating an invocation
 * of a delegate object formatter class. Delegate class, method names, method return
 * types and modifiers can be customized on the XJC command line or as binding
 * customizations.
 *
 * @author Mirko Klemm 2015-01-22
 */
public class ExpressionPlugin extends AbstractPlugin {
	public static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(ExpressionPlugin.class.getName());
	public static final String OPTION_NAME = "-Xexpression";
	public static final String CUSTOMIZATION_NS = "http://www.codesup.net/jaxb/plugins/expression";
	public static final String EXPRESSION_CUSTOMIZATION_NAME = "expression";
	public static final String EXPRESSIONS_CUSTOMIZATION_NAME = "expressions";
	public static final String EVALUATOR_CUSTOMIZATION_NAME = "evaluator";
	public static final String EVALUATOR_REF_CUSTOMIZATION_NAME = "evaluator-ref";
	public static final String EVALUATORS_CUSTOMIZATION_NAME = "evaluators";
	public static final String METHOD_CUSTOMIZATION_NAME = "method";
	public static final String CONTEXT_CUSTOMIZATION_NAME = "context";
	public static final String DEFAULT_GENERATED_METHOD_MODIFIERS = "public";
	public static final List<String> CUSTOM_ELEMENTS = Arrays.asList(
			ExpressionPlugin.EXPRESSION_CUSTOMIZATION_NAME,
			ExpressionPlugin.EXPRESSIONS_CUSTOMIZATION_NAME,
			ExpressionPlugin.EVALUATOR_CUSTOMIZATION_NAME,
			ExpressionPlugin.EVALUATOR_REF_CUSTOMIZATION_NAME,
			ExpressionPlugin.EVALUATORS_CUSTOMIZATION_NAME,
			ExpressionPlugin.CONTEXT_CUSTOMIZATION_NAME,
			ExpressionPlugin.METHOD_CUSTOMIZATION_NAME);
	public static final String DEFAULT_EVALUATOR_METHOD_NAME = "evaluate";
	public static final Method DEFAULT_METHOD_DEF;
	public static final String DEFAULT_EVALUATOR_FIELD_NAME = "__evaluator_%s";
	public static final String DEFAULT_CONTEXT_FIELD_NAME = "__CONTEXT_%s";
	public static final String DEFAULT_NAMESPACE_MAP_FIELD_NAME = "__NS_MAP_%s";
	private static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();
	private static final Pattern NS_PREFIX_PATTERN = Pattern.compile("([-\\w]+):\\w");
	private static final JAXBContext JAXB_CONTEXT;
	public static final String DEFAULT_GENERATED_METHOD_NAME = "toString";

	static {
		DEFAULT_METHOD_DEF = new Method();
		ExpressionPlugin.DEFAULT_METHOD_DEF.setNamespaceAware(false);
		ExpressionPlugin.DEFAULT_METHOD_DEF.setName(ExpressionPlugin.DEFAULT_EVALUATOR_METHOD_NAME);
		ExpressionPlugin.DEFAULT_METHOD_DEF.setLiteral(false);
		ExpressionPlugin.DEFAULT_METHOD_DEF.setTypePassing(Language.NONE);
		try {
			JAXB_CONTEXT = JAXBContext.newInstance(Expression.class, Expressions.class, Evaluator.class, Evaluators.class);
		} catch (final JAXBException e) {
			throw new RuntimeException(e);
		}
	}

	private static SAXParseException getException(final ClassOutline classOutline, final String string, final Object... args) {
		return new SAXParseException(MessageFormat.format(ExpressionPlugin.RESOURCE_BUNDLE.getString(string), args), classOutline.target.getLocator());
	}

	@Override
	public String getOptionName() {
		return ExpressionPlugin.OPTION_NAME.substring(1);
	}

	@Override
	public List<String> getCustomizationURIs() {
		return Collections.singletonList(ExpressionPlugin.CUSTOMIZATION_NS);
	}

	@Override
	public boolean isCustomizationTagName(final String nsUri, final String localName) {
		return ExpressionPlugin.CUSTOMIZATION_NS.equals(nsUri) && ExpressionPlugin.CUSTOM_ELEMENTS.contains(localName);
	}

	@Override
	public String getUsage() {
		return ExpressionPlugin.RESOURCE_BUNDLE.getString("usageText");
	}

	@Override
	public boolean run(final Outline outline, final Options opt, final ErrorHandler errorHandler) throws SAXException {
		try {
			final Map<String, EvaluatorCustomization> evaluatorMap = getEvaluators(outline.getModel());
			for (final ClassOutline classOutline : outline.getClasses()) {
				final List<ExpressionCustomization> expressions = getExpressions(classOutline.target);
				if (!expressions.isEmpty()) {
					generateMethods(errorHandler, classOutline, evaluatorMap, expressions);
				}
			}
			return false;
		} catch (final JAXBException e) {
			throw new SAXException(e);
		}
	}

	private Map<String, EvaluatorCustomization> getEvaluators(final CCustomizable customizable) throws JAXBException {
		final Map<String, EvaluatorCustomization> evaluatorMap = new LinkedHashMap<>();
		final Binder<Node> binder = ExpressionPlugin.JAXB_CONTEXT.createBinder();
		final CPluginCustomization evaluatorsCustomization = getCustomizationElement(customizable, ExpressionPlugin.EVALUATORS_CUSTOMIZATION_NAME);
		if (evaluatorsCustomization != null) {
			evaluatorsCustomization.markAsAcknowledged();
			final Evaluators evaluators = binder.unmarshal(evaluatorsCustomization.element, Evaluators.class).getValue();
			for (final Evaluator evaluator : evaluators.getEvaluator()) {
				if (evaluator.getName() == null) {
					evaluator.setName(getEvaluatorName(evaluator));
				}
				fillEvaluatorReferences(evaluator);
				evaluatorMap.put(getEvaluatorName(evaluator), new EvaluatorCustomization(evaluator, binder));
			}
		}
		final CPluginCustomization evaluatorCustomization = getCustomizationElement(customizable, ExpressionPlugin.EVALUATOR_CUSTOMIZATION_NAME);
		if (evaluatorCustomization != null) {
			evaluatorCustomization.markAsAcknowledged();
			final Evaluator evaluator = binder.unmarshal(evaluatorCustomization.element, Evaluator.class).getValue();
			if (evaluator.getName() == null) {
				evaluator.setName(getEvaluatorName(evaluator));
			}
			fillEvaluatorReferences(evaluator);
			evaluatorMap.put(getEvaluatorName(evaluator), new EvaluatorCustomization(evaluator, binder));
		}
		return evaluatorMap;
	}

	private void fillEvaluatorReferences(final Evaluator evaluator) {
		for (final Expression expression : evaluator.getExpression()) {
			if (expression.getEvaluatorName() == null) {
				expression.setEvaluatorName(evaluator.getName());
			}
			if (expression.getEvaluatorMethod() == null && !evaluator.getMethod().isEmpty()) {
				expression.setEvaluatorMethod(evaluator.getMethod().get(0).getName());
			}
		}
	}

	private List<ExpressionCustomization> getExpressions(final CCustomizable customizable) throws JAXBException {
		final List<ExpressionCustomization> expressionMap = new ArrayList<>();
		final Binder<Node> binder = ExpressionPlugin.JAXB_CONTEXT.createBinder();
		final CPluginCustomization expressionsCustomization = getCustomizationElement(customizable, ExpressionPlugin.EXPRESSIONS_CUSTOMIZATION_NAME);
		if (expressionsCustomization != null) {
			expressionsCustomization.markAsAcknowledged();
			final Expressions expressions = binder.unmarshal(expressionsCustomization.element, Expressions.class).getValue();
			for (final Expression expression : expressions.getExpression()) {
				if (expression.getEvaluatorName() == null) {
					expression.setEvaluatorName(expressions.getEvaluatorName());
				}
				if (expression.getEvaluatorMethod() == null) {
					expression.setEvaluatorMethod(expressions.getEvaluatorMethod());
				}
				expressionMap.add(new ExpressionCustomization(expression, (Element)binder.getXMLNode(expression)));
			}
		}
		final CPluginCustomization expressionCustomization = getCustomizationElement(customizable, ExpressionPlugin.EXPRESSION_CUSTOMIZATION_NAME);
		if (expressionCustomization != null) {
			expressionCustomization.markAsAcknowledged();
			final Expression expression = binder.unmarshal(expressionCustomization.element, Expression.class).getValue();
			expressionMap.add(new ExpressionCustomization(expression, expressionCustomization.element));
		}
		return expressionMap;
	}

	private String getEvaluatorName(final Evaluator evaluator) {
		if (evaluator.getName() != null) return evaluator.getName();
		if (evaluator.getClazz() == null) return null;
		final int simpleNameIndex = evaluator.getClazz().lastIndexOf('.') + 1;
		return evaluator.getClazz().substring(simpleNameIndex);
	}

	private void generateMethods(final ErrorHandler errorHandler,
	                             final ClassOutline classOutline,
	                             final Map<String, EvaluatorCustomization> globalEvaluators,
	                             final List<ExpressionCustomization> expressions)
			throws JAXBException, SAXException {
		final Outline outline = classOutline.parent();
		final JCodeModel model = outline.getCodeModel();
		final Map<String, EvaluatorCustomization> evaluators = new LinkedHashMap<>();
		final Map<String, EvaluatorCustomization> localEvaluators = getEvaluators(classOutline.target);
		final List<ExpressionCustomization> localExpressions = new ArrayList<>(expressions);
		for (final EvaluatorCustomization evaluator : localEvaluators.values()) {
			localExpressions.addAll(evaluator.expressionCustomizations);
		}
		evaluators.putAll(globalEvaluators);
		evaluators.putAll(localEvaluators);
		if (evaluators.isEmpty()) {
			evaluators.put(null,new EvaluatorCustomization(new Evaluator(), null));
			errorHandler.warning(getException(classOutline, "exception.missingFormatter"));
		}
		final Map<String, JFieldVar> evaluatorFields = new LinkedHashMap<>();
		final JDefinedClass implClass = classOutline.implClass;
		for (final ExpressionCustomization expressionCustomization : localExpressions) {
			final Expression expression = expressionCustomization.expression;
			final Evaluator evaluator = expression.getEvaluatorName() == null
					? evaluators.values().iterator().next().evaluator : evaluators.get(expression.getEvaluatorName()).evaluator;
			if (evaluator == null) {
				errorHandler.error(getException(classOutline, "exception.missingFormatter"));
				continue;
			}
			final JType methodReturnType = translateType(outline, expression);
			final String methodName = coalesce(expression.getMethodName(), createMethodName(outline, expression), ExpressionPlugin.DEFAULT_GENERATED_METHOD_NAME);
			final int modifiers = parseModifiers(coalesce(expression.getMethodAccess(), ExpressionPlugin.DEFAULT_GENERATED_METHOD_MODIFIERS));
			final JMethod generatedMethod = implClass.method(modifiers, methodReturnType, methodName);
			final JInvocation simpleInvoke;
			final String expressionSelect;
			try {
				expressionSelect = coalesce(xmlToString(expression.getAny()), expression.getSelect());
			} catch (final TransformerException e) {
				errorHandler.error(getException(classOutline, "exception.invalidExpressionContent", methodName));
				continue;
			}
			if (evaluator.getClazz() == null || evaluator.getStrategy() == EvaluatorStrategy.NONE) {
				generatedMethod.body()._return(JExpr.direct(expressionSelect));
			} else {
				final Method method = expression.getEvaluatorMethod() == null
						? evaluator.getMethod().isEmpty() ? ExpressionPlugin.DEFAULT_METHOD_DEF : evaluator.getMethod().get(0)
						: findMethod(evaluator, expression.getEvaluatorMethod());
				if (method == null) {
					errorHandler.error(getException(classOutline, "exception.missingMethod", expression.getEvaluatorMethod(), evaluator.getClazz()));
					continue;
				}
				method.setNamespaceAware(coalesce(method.isNamespaceAware(), evaluator.isNamespaceAware(), false));
				if (evaluator.getStrategy() == EvaluatorStrategy.STATIC) {
					simpleInvoke = model.ref(evaluator.getClazz()).staticInvoke(method.getName()).arg(JExpr._this());
				} else {
					JFieldVar evaluatorField = evaluatorFields.get(evaluator.getName());
					if (evaluatorField == null) {
						final JClass fieldType = model.ref(evaluator.getClazz());
						final String evaluatorFieldname = evaluator.getField() == null
								? String.format(ExpressionPlugin.DEFAULT_EVALUATOR_FIELD_NAME, outline.getModel().getNameConverter().toClassName(evaluator.getName()))
								: evaluator.getField();
						final JExpression evaluatorFieldInitExpression;
						if (evaluator.getStrategy() == EvaluatorStrategy.CLASS_INSTANCE) {
							final Context context = evaluator.getContext();
							if (context == null || context.getClazz() == null) {
								errorHandler.error(getException(classOutline, "exception.missingContext", coalesce(evaluator.getName(), evaluator.getClazz(), "-n/a-")));
								continue;
							}
							final JClass contextFieldType = model.ref(context.getClazz());
							final JFieldVar contextField = implClass.field(
									JMod.PRIVATE | JMod.STATIC | JMod.TRANSIENT,
									contextFieldType,
									context.getField() == null
											? String.format(ExpressionPlugin.DEFAULT_CONTEXT_FIELD_NAME, contextFieldType.name())
											: context.getField(),
									JExpr._new(contextFieldType).arg(implClass.dotclass())
							);
							evaluatorFieldInitExpression = implClass.staticRef(contextField).invoke(context.getMethod()).arg(JExpr._this());
						} else {
							evaluatorFieldInitExpression = JExpr._new(fieldType).arg(JExpr._this());
						}
						evaluatorField = implClass.field(
								JMod.PRIVATE | JMod.TRANSIENT,
								fieldType,
								evaluatorFieldname,
								evaluatorFieldInitExpression
						);
						evaluatorFields.put(evaluator.getName(), evaluatorField);
					}
					simpleInvoke = evaluatorField.invoke(method.getName());
				}
				final JExpression expressionLiteral = !method.isLiteral()
						? JExpr.lit(expressionSelect)
						: JExpr.direct(expressionSelect);
				simpleInvoke.arg(expressionLiteral);
				if (method.getTypePassing() == Language.JAVA) {
					if (methodReturnType instanceof JClass) {
						simpleInvoke.arg(JExpr.dotclass((JClass)methodReturnType));
					} else {
						simpleInvoke.arg(methodReturnType.boxify().dotclass());
					}
				} else if (method.getTypePassing() == Language.XML_SCHEMA) {
					final JClass qNameType = methodReturnType.owner().ref(QName.class);
					simpleInvoke.arg(JExpr._new(qNameType).arg(expression.getType().getNamespaceURI()).arg(expression.getType().getLocalPart()).arg(expression.getType().getPrefix()));
				}
				if (method.isNamespaceAware()) {
					final JFieldVar nsMapConstant = implClass.field(
							JMod.PRIVATE | JMod.STATIC | JMod.FINAL | JMod.TRANSIENT,
							model.ref(String.class).array().array(),
							String.format(ExpressionPlugin.DEFAULT_NAMESPACE_MAP_FIELD_NAME, methodName),
							findNamespaceMappings(model, expressionSelect, expressionCustomization.element)
					);
					simpleInvoke.arg(implClass.staticRef(nsMapConstant));
				}
				final JExpression invocation = JExpr.cast(methodReturnType, simpleInvoke);
				generatedMethod.body()._return(invocation);
			}
		}
	}

	static JExpression findNamespaceMappings(final JCodeModel model,final String expressionString, final Element expressionElement) {
		final JArray arrayInit = JExpr.newArray(model.ref(String.class).array());
		final Matcher matcher = ExpressionPlugin.NS_PREFIX_PATTERN.matcher(expressionString);
		final Set<String> alreadyMatchedPrefixes = new HashSet<>();
		while (matcher.find()) {
			final String namespacePrefix = matcher.group(1);
			if(alreadyMatchedPrefixes.add(namespacePrefix)) {
				final String namespaceUri = expressionElement.lookupNamespaceURI(namespacePrefix);
				if (namespaceUri != null) {
					final JArray tupleInit = JExpr.newArray(model.ref(String.class));
					tupleInit.add(JExpr.lit(namespacePrefix));
					tupleInit.add(JExpr.lit(namespaceUri));
					arrayInit.add(tupleInit);
				}
			}
		}
		return arrayInit;
	}

	private String createMethodName(final Outline outline, final Expression expression) {
		return expression == null || expression.getName() == null ? null : "get" + outline.getModel().getNameConverter().toPropertyName(expression.getName());
	}

	private JType translateType(final Outline model, final Expression expression) {
		if (expression.getType() == null) return model.getCodeModel().ref(String.class);
		for (final CBuiltinLeafInfo cinfo : model.getModel().builtins().values()) {
			if (typeMatches(expression, cinfo)) {
				return cinfo.toType(model, Aspect.EXPOSED);
			}
			for (final QName typeName : cinfo.getTypeNames()) {
				if (typeMatches(expression, typeName)) {
					return cinfo.toType(model, Aspect.EXPOSED);
				}
			}
		}
		for (final CClassInfo cinfo : model.getModel().beans().values()) {
			if (typeMatches(expression, cinfo)) {
				return cinfo.toType(model, Aspect.EXPOSED);
			}
		}
		for (final CEnumLeafInfo cinfo : model.getModel().enums().values()) {
			if (typeMatches(expression, cinfo)) {
				return cinfo.toType(model, Aspect.EXPOSED);
			}
		}
		return model.getCodeModel().ref(String.class);
	}

	private boolean typeMatches(final Expression expression, final MaybeElement<?, ?> cinfo) {
		final QName relevantName = cinfo.isElement() ? cinfo.getElementName() : cinfo.getTypeName();
		return typeMatches(expression, relevantName);
	}

	private boolean typeMatches(final Expression expression, final QName relevantName) {
		return relevantName != null && relevantName.getNamespaceURI() != null && relevantName.getLocalPart() != null
				&& relevantName.getNamespaceURI().equals(expression.getType().getNamespaceURI())
				&& relevantName.getLocalPart().equals(expression.getType().getLocalPart());
	}

	private Method findMethod(final Evaluator evaluator, final String name) {
		for (final Method method : evaluator.getMethod()) {
			if (method.getName().equals(name)) {
				return method;
			}
		}
		return null;
	}

	private int parseModifiers(final String modifiers) {
		int mod = JMod.NONE;
		for (final String token : modifiers.split("\\s+")) {
			switch (token.toLowerCase()) {
				case "public":
					mod |= JMod.PUBLIC;
					break;
				case "protected":
					mod |= JMod.PROTECTED;
					break;
				case "private":
					mod |= JMod.PRIVATE;
					break;
				case "final":
					mod |= JMod.FINAL;
					break;
				case "static":
					mod |= JMod.STATIC;
					break;
				case "abstract":
					mod |= JMod.ABSTRACT;
					break;
				case "native":
					mod |= JMod.NATIVE;
					break;
				case "synchronized":
					mod |= JMod.SYNCHRONIZED;
					break;
				case "transient":
					mod |= JMod.TRANSIENT;
					break;
				case "volatile":
					mod |= JMod.VOLATILE;
					break;
			}
		}
		return mod;
	}

	private CPluginCustomization getCustomizationElement(final CCustomizable elem, final String elementName) {
		return elem.getCustomizations().find(ExpressionPlugin.CUSTOMIZATION_NS, elementName);
	}

	private <T> T coalesce(final T... vals) {
		for (final T val : vals) {
			if (val != null)
				return val;
		}
		return null;
	}

	private String xmlToString(final Element element) throws TransformerException {
		if (element == null) return null;
		if (element.hasAttributes() || hasElements(element)) {
			// Return XML serialized to string.
			final Transformer transformer = ExpressionPlugin.TRANSFORMER_FACTORY.newTransformer();
			final StringWriter sw = new StringWriter();
			final StreamResult streamResult = new StreamResult(sw);
			transformer.transform(new DOMSource(element), streamResult);
			return sw.toString();
		} else {
			// Strip off surrounding element if content is text-only.
			return element.getTextContent();
		}
	}

	private boolean hasElements(final Node node) {
		for (int i = 0; i < node.getChildNodes().getLength(); i++) {
			final Node child = node.getChildNodes().item(i);
			if (child.getNodeType() == Node.ELEMENT_NODE) {
				return true;
			}
		}
		return false;
	}

	private static class EvaluatorCustomization {
		final Evaluator evaluator;
		final Binder<Node> binder;
		final List<ExpressionCustomization> expressionCustomizations;

		public EvaluatorCustomization(final Evaluator evaluator, final Binder<Node> binder) {
			this.evaluator = evaluator;
			this.binder = binder;
			this.expressionCustomizations = new ArrayList<>(evaluator.getExpression().size());
			for (final Expression expression : evaluator.getExpression()) {
				this.expressionCustomizations.add(new ExpressionCustomization(expression, (Element)this.binder.getXMLNode(expression)));
			}
		}
	}

	private static class ExpressionCustomization {
		final Expression expression;
		final Element element;

		public ExpressionCustomization(final Expression expression, final Element element) {
			this.expression = expression;
			this.element = element;
		}
	}
}
