# exist-bcrypt
bcrypt module for eXist-db

module namespace: "http://max.terpstra.ca/ns/exist-bcrypt"

Provides three functions:

 * `bcrypt:hash($password as xs:string) as xs:string`
 * `bcrypt:hash($password as xs:string, $work as xs:positiveInteger) as xs:string`
 * `bcrypt:matches($hash as xs:string, $plain as xs:string) as xs:boolean`
