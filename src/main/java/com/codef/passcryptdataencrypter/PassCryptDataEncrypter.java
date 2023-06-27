package com.codef.passcryptdataencrypter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

public class PassCryptDataEncrypter {

	/* Safe to configure as needed */
	private static final String DATA_DRIVE_AND_FOLDER = "E:\\PassCryptDataEncrypter\\";
	private static final String PASSWORD_FOR_PASSCRYPT_APP = "bobolala69!";

	/* probably don't want to mess with these */
	private static final String ALGORITHM = "AES";
	private static final int KEY_LENGTH = 128;

	private static final String DATA_IN_FOLDER = DATA_DRIVE_AND_FOLDER + "IN\\";
	private static final String DATA_OUT_FOLDER = DATA_DRIVE_AND_FOLDER + "OUT\\";

	private static final String XML_DATA_FILE_TEMPLATE = "CryptPasswords.xml";
	private static final String XML_DATA_FILE_FOR_PASSCRYPT = "site_passwords_secure.xml";

	private static final String EXPORT_FOR_PHONE_CONSTANT = "Export_For_Phone";
	private static final String ENCRYPTED_CONST = "ENCRYPTED";

	private static List<String> cleanupLinesThatContain = new ArrayList<String>();

	protected static Map<String, TreeMap<String, String>> passwordMap = new TreeMap<>();

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

		// These are my standard cleanup lines in my template
		cleanupLinesThatContain.add(ENCRYPTED_CONST); // do not remove this one
		cleanupLinesThatContain.add(EXPORT_FOR_PHONE_CONSTANT); // do not remove this one
		cleanupLinesThatContain.add("Last_Update");

		buildSampleResourcesAndFolder();
		copyXMLDocumentForExport();
		handleCryptsAndCleanXMLDoc();
		
		System.out.println("Done!");

	}

	public static void buildSampleResourcesAndFolder() throws IOException {
		makeDirectory(DATA_DRIVE_AND_FOLDER);
		makeDirectory(DATA_IN_FOLDER);
		makeDirectory(DATA_OUT_FOLDER);

		File testFile = new File(DATA_IN_FOLDER + XML_DATA_FILE_TEMPLATE);
		if (!testFile.exists()) {
			ClassLoader classLoader = ClassLoader.getSystemClassLoader();
			copyFile(classLoader.getResource(XML_DATA_FILE_TEMPLATE).getPath(),
					DATA_IN_FOLDER + XML_DATA_FILE_TEMPLATE);
		}

	}

	public static void copyXMLDocumentForExport() {

		String sourceDoc = DATA_IN_FOLDER + XML_DATA_FILE_TEMPLATE;
		String targetDoc = DATA_OUT_FOLDER + XML_DATA_FILE_FOR_PASSCRYPT;

		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();

			Document originalDoc = builder.parse(sourceDoc);
			Document copiedDoc = builder.newDocument();

			Element newRootElement = copiedDoc.createElement("SitePasswords");
			copiedDoc.appendChild(newRootElement);

			NodeList nodeList = originalDoc.getElementsByTagName(EXPORT_FOR_PHONE_CONSTANT);
			for (int i = 0; i < nodeList.getLength(); i++) {
				Node node = nodeList.item(i);
				if (node.getTextContent().equals("true")) {
					Element parentElement = (Element) node.getParentNode();
					if (!parentElement.getNodeName().equals("SitePasswords")) {
						Element copiedNode = copyElement(parentElement, copiedDoc);
						newRootElement.appendChild(copiedNode);
					}
				}
			}
			saveXMLDocument(copiedDoc, targetDoc);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static Element copyElement(Element originalElement, Document targetDocument) {
		Element copiedElement = targetDocument.createElement(originalElement.getTagName());

		// Copy the attributes
		NamedNodeMap attributes = originalElement.getAttributes();
		for (int i = 0; i < attributes.getLength(); i++) {
			Attr attribute = (Attr) attributes.item(i);
			copiedElement.setAttribute(attribute.getName(), attribute.getValue());
		}

		// Copy the child nodes recursively
		NodeList childNodes = originalElement.getChildNodes();
		for (int i = 0; i < childNodes.getLength(); i++) {
			Node child = childNodes.item(i);
			if (child.getNodeType() == Node.ELEMENT_NODE) {
				Element copiedChildElement = copyElement((Element) child, targetDocument);
				copiedElement.appendChild(copiedChildElement);
			} else if (child.getNodeType() == Node.TEXT_NODE) {
				Text copiedText = targetDocument.createTextNode(child.getTextContent());
				copiedElement.appendChild(copiedText);
			}
		}

		return copiedElement;
	}

	private static void saveXMLDocument(Document document, String targetDoc) throws TransformerException {

		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

		DOMSource source = new DOMSource(document);
		StreamResult result = new StreamResult(targetDoc);
		transformer.transform(source, result);

	}

	public static void decryptFile(String inputFile, String outputFile, String key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {

		SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		try (InputStream inputStream = new FileInputStream(inputFile);
				OutputStream outputStream = new FileOutputStream(outputFile)) {

			CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);

			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
				outputStream.write(buffer, 0, bytesRead);
			}

			cipherInputStream.close();
		}
	}

	public static String decryptFileToString(String inputFile, String key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {

		SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);

		try (InputStream inputStream = new FileInputStream(inputFile)) {
			CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
				outputStream.write(buffer, 0, bytesRead);
			}

			cipherInputStream.close();

			return new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
		}
	}

	public static void encryptFile(String inputFile, String outputFile, String key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {

		SecretKey secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);

		try (InputStream inputStream = new FileInputStream(inputFile);
				OutputStream outputStream = new FileOutputStream(outputFile)) {

			CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);

			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = inputStream.read(buffer)) != -1) {
				cipherOutputStream.write(buffer, 0, bytesRead);
			}

			cipherOutputStream.close();
		}
	}

	public static void handleCryptsAndCleanXMLDoc() throws NoSuchAlgorithmException {

		String fileName = DATA_OUT_FOLDER + XML_DATA_FILE_FOR_PASSCRYPT;
		String secretKey = generateAESKeyAsString();

		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document document = builder.parse(fileName);
			Element root = document.getDocumentElement();
			NodeList childNodes = root.getChildNodes();
			for (int i = 0; i < childNodes.getLength(); i++) {
				Node child = childNodes.item(i);
				if (child.getNodeType() == Node.ELEMENT_NODE) {
					Element element = (Element) child;

					String nodeName = element.getNodeName();
					String userName = "";
					String password = "";
					String email = "";

					NodeList testList = element.getElementsByTagName("Username");
					if (testList.getLength() > 0) {
						userName = element.getElementsByTagName("Username").item(0).getTextContent();
						element.getElementsByTagName("Username").item(0).setTextContent(ENCRYPTED_CONST);
					}

					testList = element.getElementsByTagName("Password");
					if (testList.getLength() > 0) {
						password = element.getElementsByTagName("Password").item(0).getTextContent();
						element.getElementsByTagName("Password").item(0).setTextContent(ENCRYPTED_CONST);
					}

					testList = element.getElementsByTagName("EMail_Address");
					if (testList.getLength() > 0) {
						email = element.getElementsByTagName("EMail_Address").item(0).getTextContent();
						element.getElementsByTagName("EMail_Address").item(0).setTextContent(ENCRYPTED_CONST);
					}

					StringBuilder sb = new StringBuilder();
					sb.append(nodeName + ":" + "\n");
					sb.append("\t" + "   E-Mail: " + email + "\n");
					sb.append("\t" + "User Name: " + userName + "\n");
					sb.append("\t" + " Password: " + password + "\n");

					writeStringToFile(sb.toString(), DATA_OUT_FOLDER + nodeName.toLowerCase() + ".txt");
					encryptFile(DATA_OUT_FOLDER + nodeName.toLowerCase() + ".txt",
							DATA_OUT_FOLDER + nodeName.toLowerCase() + ".enc", secretKey);

//					decryptFile(DATA_OUT_FOLDER + nodeName.toLowerCase() + ".enc", DATA_OUT_FOLDER + nodeName.toLowerCase() + ".dec", secretKey);
//					String decodedStuff = decryptFileToString(DATA_OUT_FOLDER + nodeName.toLowerCase() + ".enc", secretKey);
//					System.out.println(decodedStuff);

					deleteFileNew(DATA_OUT_FOLDER + nodeName.toLowerCase() + ".txt");

				}
			}

			saveXMLDocument(document, fileName);
			writeStringToFile(secretKey, DATA_OUT_FOLDER + "secret.key");
			writeStringToFile(PASSWORD_FOR_PASSCRYPT_APP, DATA_OUT_FOLDER + "passcrypt.key");

			cleanUpLinesInXMLDoc(fileName);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static String generateAESKeyAsString() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(KEY_LENGTH);
		SecretKey secretKey = keyGenerator.generateKey();
		byte[] keyBytes = secretKey.getEncoded();
		String newKey = Base64.getEncoder().encodeToString(keyBytes);
		return newKey;
	}

	private static void cleanUpLinesInXMLDoc(String fileName) throws IOException {

		StringBuilder sb = new StringBuilder();
		List<String> fileLines = Files.readAllLines(Paths.get(fileName), StandardCharsets.UTF_8);

		for (String line : fileLines) {
			boolean keepLine = true;
			if (line.trim().length() > 0) {
				for (String singleCleanupLine : cleanupLinesThatContain) {
					if (line.contains(singleCleanupLine)) {
						keepLine = false;
					}
				}
				if (keepLine) {
					sb.append(line).append("\n");
				}
			}
		}

		writeStringToFile(sb.toString(), fileName);

	}

	private static synchronized void writeStringToFile(String dataToWrite, String filePath) throws IOException {
		Files.write(Paths.get(filePath), dataToWrite.getBytes());
	}

	private static void makeDirectory(String pathToDirectory) {
		File directory = new File(pathToDirectory);
		if (!directory.exists()) {
			directory.mkdirs();
		}
	}

	public static void copyFile(String sourcePath, String destinationPath) throws IOException {
		Files.copy(new File(sourcePath).toPath(), new File(destinationPath).toPath());
	}

	private static void deleteFileNew(String pathToFile) throws IOException {
		Path filePath = Paths.get(pathToFile);
		Files.delete(filePath);
	}

	// OLD CLEANUP STUFF
	// ---------------------------------------------------------------------

	// grabing the default username
	/*
	String userName = "PROBLEM_NO_USERNAME_FOUND";
	try {
		userName = element.getElementsByTagName("Username").item(0).getTextContent();
		if (!userName.contains("@")) {
			userName = "PROBLEM_NO_EMAIL_FOUND";
		}
	} catch (Exception e) {
	}
	*/

	// Make sure there is a EMail_Address node, if not, create node with possible
	// e-mail being the username
	/*
	try {
		element.getElementsByTagName("EMail_Address").item(0).getTextContent();
	} catch (Exception e) {
		Element textNodeElement = document.createElement("EMail_Address");
		Text textNode = document.createTextNode(userName);
		textNodeElement.appendChild(textNode);
		element.appendChild(textNodeElement);
	}
	*/

	// make sure it has a password node
	/*
	try {
		element.getElementsByTagName("Password").item(0).getTextContent();
	} catch (Exception e) {
		System.out.println("Password missing for " + nodeName);
	}
	*/

	// Add the export for vacation feature
	/*
	Element textNodeElement = document.createElement("Export_For_Phone");
	Text textNode = document.createTextNode("false");
	textNodeElement.appendChild(textNode);
	element.appendChild(textNodeElement);
	*/

}
