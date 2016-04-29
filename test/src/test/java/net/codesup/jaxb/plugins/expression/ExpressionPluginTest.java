package net.codesup.jaxb.plugins.expression;

import org.junit.Assert;
import org.junit.Test;

import net.codesup.jaxb.plugins.expression.test.GlobalDefaultrefSingle;

/**
 * Created by klemm0 on 2016-04-29.
 */
public class ExpressionPluginTest {
	@Test
	public void testGlobalDefaultrefSingle() throws Exception {
		GlobalDefaultrefSingle r = new GlobalDefaultrefSingle();
		r.setAutoLogon(true);
		r.setUserId("klemm0");
		r.setUserFirstName("Mirko");
		r.setUserLastName("Klemm");
		Assert.assertEquals("klemm0 - Klemm, Mirko", r.toString());
	}
}
