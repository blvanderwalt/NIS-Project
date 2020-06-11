#Directories:
#bin dir containing class files
BINDIR=./bin
#src dir containiing java files
SRCDIR=./src
#doc dir containing java docs
DOCDIR=./doc
CLASSPATH=".;bcprov-jdk15on-165.jar;bcpkix-jdk15on-165.jar;./bin;"

.SUFFIXES: .java .class

# -cp => specified CLASSPATH
# -d  => where to write .class files

# Build rules:
#=============
#Server depends on: ServerClient, OurSigner, Encryption, Authentication, Message
${BINDIR}/Server.class: ${BINDIR}/ServerClient.class ${BINDIR}/OurSigner.class ${BINDIR}/Encryption.class ${BINDIR}/Authentication.class  ${BINDIR}/Message.class ${SRCDIR}/Server.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/Server.java

#Test depends on: OurSigner, Encryption, Authentication, Message
${BINDIR}/Test.class: ${BINDIR}/OurSigner.class ${BINDIR}/Encryption.class ${BINDIR}/Authentication.class  ${BINDIR}/Message.class ${SRCDIR}/Test.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/Test.java
	
#ServerClient depends on: Encryption, Message
${BINDIR}/ServerClient.class: ${BINDIR}/Encryption.class ${BINDIR}/Message.class ${SRCDIR}/ServerClient.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/ServerClient.java
	
#Client depends on: Encryption, Message, OurSigner, Authentication
${BINDIR}/Client.class: ${BINDIR}/OurSigner.class ${BINDIR}/Encryption.class ${BINDIR}/Authentication.class  ${BINDIR}/Message.class ${SRCDIR}/Client.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/Client.java
	
#Authentication depends on: Encryption, Message
${BINDIR}/Authentication.class: ${BINDIR}/Encryption.class ${BINDIR}/Message.class ${SRCDIR}/Authentication.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/Authentication.java ${SRCDIR}/Message.java
	
#Message depends on: Encryption, Authentication
${BINDIR}/Message.class: ${BINDIR}/Encryption.class ${BINDIR}/Authentication.class ${SRCDIR}/Message.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/Message.java ${SRCDIR}/Authentication.java
	
${BINDIR}/OurSigner.class:  ${SRCDIR}/OurSigner.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/OurSigner.java
	
${BINDIR}/Encryption.class:  ${SRCDIR}/Encryption.java
	javac -classpath ${CLASSPATH} -d ${BINDIR} ${SRCDIR}/Encryption.java

# Default make
default: ${BINDIR}/Server.class ${BINDIR}/Client.class ${BINDIR}/Test.class

#Run Server
server: ${BINDIR}/Server.class
	java -classpath ${CLASSPATH}/ Server
	
#Run Client
client: ${BINDIR}/Client.class
	java -classpath ${CLASSPATH}/ Client
	
#Run Test
test: ${BINDIR}/Test.class
	java -classpath ${CLASSPATH}/ Test
	
	
# Deletes all project class files, in bin
clean:
	rm -f ${BINDIR}/*.class

# Generates the needed javadocs
docs:
	javadoc  -classpath ${CLASSPATH} -d ${DOCDIR} ${SRCDIR}/*.java

# Deletes the existing javadocs
cleandocs:
	rm -rf ${DOCDIR}/*


