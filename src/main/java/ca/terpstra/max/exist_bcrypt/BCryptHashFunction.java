package ca.terpstra.max.exist_bcrypt;

import org.exist.xquery.*;
import org.exist.xquery.value.*;
import org.exist.dom.QName;

import org.mindrot.jbcrypt.BCrypt;

public class BCryptHashFunction extends BasicFunction {
    private final static FunctionParameterSequenceType password =
    	new FunctionParameterSequenceType(
			"password",
			Type.STRING,
			Cardinality.EXACTLY_ONE,
			"the password to hash"
		);
    private final static FunctionReturnSequenceType hash =
    	new FunctionReturnSequenceType(
			Type.STRING,
			Cardinality.EXACTLY_ONE,
			"the hash value"
		);

	public final static FunctionSignature[] SIGNATURES = {
		/* bcrypt:hash($password as xs:string) as xs:string */
		new FunctionSignature(
			new QName("hash", BCryptModule.NAMESPACE_URI, BCryptModule.PREFIX),
			"Hash a password using bcrypt",
			new SequenceType[] { password },
			hash
		),
		/* bcrypt:hash($password as xs:string, $work as xs:positiveInteger) as xs:string */
		new FunctionSignature(
			new QName("hash", BCryptModule.NAMESPACE_URI, BCryptModule.PREFIX),
			"Hash a password using bcrypt",
			new SequenceType[] {
				password,
				new FunctionParameterSequenceType(
					"work",
					Type.POSITIVE_INTEGER,
					Cardinality.EXACTLY_ONE,
					"the log2 of the number of rounds of hashing to apply"
				)
			},
			hash
		)
	};

	public BCryptHashFunction(XQueryContext ctx, FunctionSignature sig) {
		super(ctx, sig);
	}

	@Override
	public Sequence eval(Sequence[] args, Sequence ctx) throws XPathException {
		assert(args.length == 1 || args.length == 2);
		int rounds = BCryptModule.DEFAULT_WORK;
		if (args.length == 2) {
			rounds = ((IntegerValue)args[1].convertTo(Type.POSITIVE_INTEGER)).getInt();
		}
		return new StringValue(
			BCrypt.hashpw(
				args[0].getStringValue(),
				BCrypt.gensalt(rounds)
			)
		);
	}
}