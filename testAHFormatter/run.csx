#r "XfoDotNet40Ctl65.dll"
#r "itextsharp.dll"
#r "Newtonsoft.Json"

using System.Net;
using System.Net.Http;
using XfoDotNetCtl;
using System;
using System.IO;
using System.Xml.Xsl;
using System.Xml.XPath;
using Newtonsoft.Json;
using System.Xml;
using Saxon.Api;
using System.Text;
using Org.BouncyCastle.Pkcs;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;


public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log, ExecutionContext context)
{
   log.Info("AHFormatter function isprocessing a request.");

   string homeloc = context.FunctionDirectory;
   string rootloc = Directory.GetParent(homeloc).FullName;

   dynamic body = req.Content.ReadAsStringAsync().Result;
   dynamic json = JsonConvert.DeserializeObject(body);
   string xml = json.xml;
   xml = WebUtility.HtmlDecode(xml);

   // Removing possible BOM chars
   int index = xml.IndexOf('<');
   if (index > 0)
   {
       xml = xml.Substring(index, xml.Length - index);
   }
   string xsl = json.xsl;
   //xsl = WebUtility.HtmlDecode(xsl);

   bool signpdf = false;
   try { 
       signpdf = json.signpdf;
   } catch (Exception ex){}
   bool lockpdfwithpassword = false;
   try
   {
       lockpdfwithpassword = json.lockpdfwithpassword;
   }
   catch (Exception ex){}

   MemoryStream outFs = new MemoryStream();

   XfoObj obj = null;
   try
   {
       obj = new XfoObj();
       obj.ErrorStreamType = 2;
       obj.ExitLevel = 4;

       Stream inFo = doXSLT20(xml, xsl);
       obj.Render(inFo, outFs);

       // Read stream into byte array.
       byte[] byteArray = outFs.ToArray();
       if (signpdf || lockpdfwithpassword)
       {
           MemoryStream ss = new MemoryStream();
           DigiSignPdf(byteArray, ss, new FileStream(rootloc+ "/cert/GrECo-TestPDFSigningCertificate-pwd_GrECo-Test.pfx", FileMode.Open),"GrECo-Test","I love signing","Somewhere on the cloud","Sasa Bojanic",signpdf,lockpdfwithpassword ? "enhydra" : null,false);
           byteArray = ss.ToArray();
       }

       var result = req.CreateResponse();
       result.StatusCode = HttpStatusCode.OK;
       result.Content = new ByteArrayContent(byteArray);
       result.Content.Headers.Add("Content-Type", "application/pdf");

       return result;
   }
   catch (XfoException e)
   {
       Console.WriteLine("ErrorLevel = " + e.ErrorLevel + "\nErrorCode = " + e.ErrorCode + "\n" + e.Message);
       throw e;
   }
   catch (Exception e)
   {
       Console.WriteLine(e.Message);
       throw e;
   }
   finally
   {
       if (outFs != null)
           outFs.Close();
       if (obj != null)
           obj.Dispose();
   }

   //return null;
}

static Stream doXSLT20(string xml, string xsl)
{
   // Compile stylesheet
   var processor = new Processor();
   var compiler = processor.NewXsltCompiler();
   var executable = compiler.Compile(new Uri(xsl));

   // Load the source document
   byte[] byteArray = Encoding.UTF8.GetBytes(xml);
   MemoryStream xmlstream = new MemoryStream(byteArray);

   // Do transformation to a destination
   var transformer = executable.Load();
   transformer.SetInputStream(xmlstream, new Uri(xsl));

   MemoryStream inFo = new MemoryStream();
   Serializer serializer = new Serializer();
   serializer.SetOutputStream(inFo);
   transformer.Run(serializer);


   return inFo;
}

public static void DigiSignPdf(byte[] source,
       Stream destinationStream,
       Stream privateKeyStream,
       string keyPassword,
       string reason,
       string location,
       string contact,
       bool signPdf,
       string pdfpassword,
       bool isVisibleSignature)
{
   // reader and stamper
   PdfReader reader = new PdfReader(source);
   PdfStamper stamper = null;
   if (signPdf)
   {
       stamper = PdfStamper.CreateSignature(reader, destinationStream, '\0');
   } else
   {
       stamper = new PdfStamper(reader, destinationStream);
   }
   // password protection
   if (pdfpassword!=null)
   {
       byte[] pwd = Encoding.UTF8.GetBytes(pdfpassword);
       stamper.SetEncryption(pwd, pwd, PdfWriter.AllowPrinting, PdfWriter.ENCRYPTION_AES_128);
   }

   if (signPdf)
   {
       Pkcs12Store pk12 = new Pkcs12Store(privateKeyStream, keyPassword.ToCharArray());
       privateKeyStream.Dispose();

       //then Iterate throught certificate entries to find the private key entry
       string alias = null;
       foreach (string tAlias in pk12.Aliases)
       {
           if (pk12.IsKeyEntry(tAlias))
           {
               alias = tAlias;
               break;
           }
       }
       var pk = pk12.GetKey(alias).Key;


       // appearance
       PdfSignatureAppearance appearance = stamper.SignatureAppearance;
       //appearance.Image = new iTextSharp.text.pdf.PdfImage();
       appearance.Reason = reason;
       appearance.Location = location;
       appearance.Contact = contact;
       if (isVisibleSignature)
       {
           appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(20, 10, 170, 60), reader.NumberOfPages, null);
       }
       // digital signature
       IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");
       MakeSignature.SignDetached(appearance, es, new Org.BouncyCastle.X509.X509Certificate[] { pk12.GetCertificate(alias).Certificate }, null, null, null, 0, CryptoStandard.CMS);
   }
   stamper.Close();
   reader.Close();
   reader.Dispose();
}
