package ca.terpstra.max.exist_bcrypt;

import org.exist.xquery.*;
import org.exist.xquery.value.*;
import org.exist.dom.QName;

import org.mindrot.jbcrypt.BCrypt;

public class BCryptMatchesFunction extends BasicFunction {
	/* bcrypt:matches($hash as xs:string, $plain as xs:string) as xs:boolean */
	public final static FunctionSignature SIGNATURE = new FunctionSignature(
		new QName("matches", BCryptModule.NAMESPACE_URI, BCryptModule.PREFIX),
		"Check that a plain text password matches a previously hashed one",
		new SequenceType[] {
			new FunctionParameterSequenceType(
				"hash",
				Type.STRING,
				Cardinality.ZERO_OR_ONE,
				"the previously hashed password"
			),
			new FunctionParameterSequenceType(
				"plain",
				Type.STRING,
				Cardinality.EXACTLY_ONE,
				"the plain text password to verify"
			)			
		},
		new FunctionReturnSequenceType(
			Type.BOOLEAN,
			Cardinality.EXACTLY_ONE,
			"true() if the given plain text password matches the given hash"
		)
	);

	public BCryptMatchesFunction(XQueryContext ctx, FunctionSignature sig) {
		super(ctx, sig);
	}

	@Override
	public Sequence eval(Sequence[] args, Sequence ctx) throws XPathException {
		assert(args.length == 2);
		if (args[0].isEmpty()) {
			return new BooleanValue(false);
		} else {
			return new BooleanValue(
				BCrypt.checkpw(
					args[1].getStringValue(),
					args[0].getStringValue()
				)
			);
		}
	}
}
