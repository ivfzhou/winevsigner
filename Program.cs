/*
 * Copyright (c) 2023 ivfzhou
 * winevsigner is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.IO.Packaging;

namespace winevsigner
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // 证书指纹
            var thumprint = args[0];
            // 待签名文件路径
            var filePath = args[1];
            // 获取当前用户个人证书库下的证书
            X509Store certs = new X509Store("My", StoreLocation.CurrentUser);
            certs.Open(OpenFlags.ReadOnly);
            // 根据指纹找出证书
            X509Certificate2 cert = null;
            foreach (X509Certificate2 v in certs.Certificates)
            {
                if (string.Compare(v.Thumbprint, thumprint, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    cert = v;
                    break;
                }
            }
            if (cert == null)
            {
                // 未找到证书
                Console.Error.WriteLine("certificate not found");
                Environment.Exit(1);
            }
            // 执行签名
            Package apk = null;
            try
            {
                apk = Package.Open(filePath);
                PackageDigitalSignatureManager manager = new PackageDigitalSignatureManager(apk)
                {
                    CertificateOption = CertificateEmbeddingOption.InCertificatePart
                };
                List<Uri> list = new List<Uri>();
                foreach (PackagePart v in apk.GetParts())
                {
                    list.Add(v.Uri);
                }
                List<PackageRelationshipSelector> prs = new List<PackageRelationshipSelector>();
                foreach (PackageRelationship v in apk.GetRelationships())
                {
                    prs.Add(new PackageRelationshipSelector(v.SourceUri, PackageRelationshipSelectorType.Type, v.RelationshipType));
                }
                PackageDigitalSignature sign = manager.Sign(list, cert, prs);
                Console.WriteLine(BitConverter.ToString(sign.SignatureValue).Replace("-", ""));
            }
            finally
            {
                apk?.Close();
            }
        }
    }
}
