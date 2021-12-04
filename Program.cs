using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace GenerateAESKey
{
    class Program
    {
        private static readonly string _libraryPath = @"C:\Program Files\Utimaco\CryptoServer\Lib\cs_pkcs11_R2.dll";
        //private static string _libraryPath = @"C:\Program Files\SafeNet\LunaClient\cryptoki.dll";
        private static readonly ulong _slotId = 0L;
        //private static ulong _slotId = 1L;
        private static readonly string _userPin = "";
        //private static string _userPin = "";

        private static readonly string RSAKeyLabel = "";

        //private static string AESKeyLabel = "SecretKey01";
        private static readonly string AESKeyLabel = "SecretKey01";
        //private bool _disposed = false;
        private IPkcs11Library _pkcs11;
        private ISlot _pkcs11Slot;
        IObjectHandle _privateKey;
        IObjectHandle _publicKey;
        IObjectHandle _secretKey;

        static void Main(string[] args)
        {
            Program program = new Program();
            program._init();
            program.wrapKey();
            //program.GenerateAESKey();
            //program.GenKeyPair();
            Console.ReadKey();
        }

        private void _init()
        {
            if (string.IsNullOrEmpty(_libraryPath))
            {
                throw new ArgumentNullException("Library path is required");
            }

            if (!File.Exists(_libraryPath))
            {
                throw new ArgumentNullException("Library file is not exist");
            }

            try
            {
                if (_pkcs11 != null)
                {
                    _pkcs11.Dispose();
                    _pkcs11 = null;
                }

                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                _pkcs11 = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, _libraryPath, AppType.SingleThreaded);

                _pkcs11Slot = _getSlot(_slotId);
                ISession session = _pkcs11Slot.OpenSession(SessionType.ReadWrite);
                // Bypass this exception
                try
                {
                    session.Login(CKU.CKU_USER, _userPin);
                }
                catch (Pkcs11Exception e)
                {
                    if (e.RV != CKR.CKR_OK && e.RV != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    {
                        throw new Exception("" + e.RV);
                    }
                    else
                    {
                        Exception ex = new Exception(String.Format("{0}-SessionID:{1}-{2}", "InitProcess", session.SessionId, e.ToString()));

                        throw ex;
                    }

                }
            }
            catch (Pkcs11Exception ex)
            {
                throw ex;
            }
        }

        public IObjectHandle FindAESKey(ISession session)
        {
            List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, AESKeyLabel)
            };

            //if (!string.IsNullOrEmpty(ckaLabel))
            //    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "SecretKey01"));


            List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);
            if (foundObjects.Count < 1)
                throw new Exception(string.Format("Private key with label \"{0}\" and id \"{1}\" was not found",
                    AESKeyLabel));
            else if (foundObjects.Count > 1)
                throw new Exception(string.Format("More than one private key with label \"{0}\" and id \"{1}\" was found",
                    AESKeyLabel));

            return foundObjects[0];
        }

        public static byte[] CreateDigestInfo(byte[] hash, string hashOid)
        {
            DerObjectIdentifier derObjectIdentifier = new DerObjectIdentifier(hashOid);
            AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(derObjectIdentifier, null);
            DigestInfo digestInfo = new DigestInfo(algorithmIdentifier, hash);
            return digestInfo.GetDerEncoded();
        }

        public static byte[] CreateDigestInfo(byte[] data)
        {
            byte[] digest = null;
            byte[] digestInfo = null;
            HashAlgorithm alg = HashAlgorithm.SHA1;
            digest = ComputeDigest(new Sha1Digest(), data);
            digestInfo = CreateDigestInfo(digest, "1.3.14.3.2.26");
            return digestInfo;
        }

        public static byte[] ComputeDigest(IDigest digest, byte[] data)
        {
            if (digest == null)
                throw new ArgumentNullException("digest");

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] hash = new byte[digest.GetDigestSize()];

            digest.Reset();
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;
        }

        public enum HashAlgorithm
        {
            SHA1,
            SHA256,
            SHA384,
            SHA512
        }

        public void wrapKey()
        {
            using (ISession session = _pkcs11Slot.OpenSession(SessionType.ReadWrite))
            {
                try
                {
                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, AESKeyLabel)
                    };

                    // Get search results
                    List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);

                    if (foundObjects.Count < 1)
                        throw new Exception(string.Format("Secret key was not found"));

                    _secretKey = foundObjects[0];
                    _privateKey = _findPrivateKey(session, RSAKeyLabel, null);

                    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_AES_ECB);
                    byte[] wrappedKey = session.WrapKey(mechanism, _secretKey, _privateKey);
                    string a = ConvertUtils.BytesToBase64String(wrappedKey);
                    if (wrappedKey != null)
                    {
                        Console.WriteLine("wrap key thanh cong!");
                    }
                    else
                    {
                        Console.WriteLine("wrap loi");
                    }
                    List<IObjectAttribute> attributes = new List<IObjectAttribute>
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, RSAKeyLabel),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true)
                    };
                    IObjectHandle unwrappedKey = session.UnwrapKey(mechanism, _secretKey, wrappedKey, attributes);

                    _secretKey = foundObjects[0];
                    byte[] wrappedKeyB = session.WrapKey(mechanism, _secretKey, unwrappedKey);
                    string b = ConvertUtils.BytesToBase64String(wrappedKeyB);
                    if (a == b)
                    {
                        Console.WriteLine("unwrap thanh cong!");
                    }
                    else
                    {
                        Console.WriteLine("unwraploi");
                    }
                }
                catch (Pkcs11Exception e)
                {
                    throw e;
                }
            }
        }

        private ISlot _getSlot(ulong slotId)
        {
            var slotList = _pkcs11.GetSlotList(SlotsType.WithTokenPresent);
            if (slotList == null || slotList.Count < 1)
            {
                return null;
            }
            foreach (ISlot slot in slotList)
            {
                ITokenInfo tokenInfo = null;

                try
                {
                    tokenInfo = slot.GetTokenInfo();
                }
                catch (Pkcs11Exception ex)
                {
                    if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                        throw;
                }

                if (tokenInfo == null)
                    continue;

                if (slot.SlotId == slotId)
                {
                    return slot;
                }
            }

            return null;
        }

        private IObjectHandle _findPrivateKey(ISession session, string privateKeyLabel, byte[] privateKeyId)
        {
            List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, privateKeyLabel)
            };

            List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);
            if (foundObjects.Count < 1)
                throw new Exception(string.Format("Private key with label \"{0}\" and id \"{1}\" was not found",
                    privateKeyLabel, ConvertUtils.BytesToHexString(privateKeyId)));
            else if (foundObjects.Count > 1)
                throw new Exception(string.Format("More than one private key with label \"{0}\" and id \"{1}\" was found",
                    privateKeyLabel, ConvertUtils.BytesToHexString(privateKeyId)));

            return foundObjects[0];
        }

        public void GenerateAESKey()
        {
            using (ISession session = _pkcs11Slot.OpenSession(SessionType.ReadWrite))
            {
                byte[] AESKeyLabel = Encoding.ASCII.GetBytes("AES Secret Key");

                List<IObjectAttribute> AESKey = new List<IObjectAttribute>
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, AESKeyLabel),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true)
                };

                session.CreateObject(AESKey);

            }
        }

        public void GenKeyPair()
        {
            using (ISession session = _pkcs11Slot.OpenSession(SessionType.ReadWrite))
            {
                byte[] rsaPrvKeyLb = Encoding.ASCII.GetBytes("Private Key Test");
                byte[] rsaPubKeyLb = Encoding.ASCII.GetBytes("Public Key Test");

                List<IObjectAttribute> rsaPrvKeyAttr = new List<IObjectAttribute>
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, rsaPrvKeyLb),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                    //session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                    //session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA)
                    //session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true)
                };

                List<IObjectAttribute> rsaPubKeyAttr = new List<IObjectAttribute>
                {
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, rsaPubKeyLb),                   
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048),
                    
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                    //session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                    session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA)
                };
                
                IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
                session.GenerateKeyPair(mechanism, rsaPubKeyAttr, rsaPrvKeyAttr, out _publicKey, out _privateKey);
            }
        }
    }
}
