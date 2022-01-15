using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using GatewayServer.Module;
using GatewayServer.Module.Config;
using NLog;
using Replace.Common;
using Replace.Common.AsyncNetwork;
using Replace.Common.Certification;
using Replace.Common.Gateway;
using Replace.Common.Security;

namespace GatewayServer.Client
{
    internal class ClientInterface : IAsyncInterface
    {
        private static Logger _logger = LogManager.GetLogger(nameof(ClientInterface));

        public bool OnConnect(AsyncContext context)
        {

            ClientData clientData = new ClientData
            {
                Connected = true, CertificationManager = context.User as CertificationManager
            };

            context.User = clientData;
           
            return true;

            //throw new NotImplementedException();
        }

        public void OnDisconnect(AsyncContext context)
        {
            throw new NotImplementedException();
        }

        public void OnError(AsyncContext context, object user)
        {
            throw new NotImplementedException();
        }

        public bool OnReceive(AsyncContext context, byte[] buffer, int count)
        {
            ClientData clientData = (ClientData)context.User;
            clientData.Context = context;

            try
            {
                clientData.SecurityManager.Recv(buffer, 0, count);

                List<Packet> packets = clientData.SecurityManager.TransferIncoming();

                if (packets != null)
                {
                    foreach (Packet packet in packets)
                    {
                        //byte[] payload = packet.GetBytes();
                        //Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);

                        switch (packet.Opcode)
                        {
                            case 0x5000:
                            case 0x9000:
                            case 0x2001:
                                continue;

                            case (ushort)ClientOpcode.CLIENT_GATEWAY_PATCH_REQUEST:
                                OnPatchRequest(packet, clientData, context);
                                break;

                            case (ushort)ClientOpcode.CLIENT_GATEWAY_NOTICE_REQUEST:
                                OnNoticeRequest(packet, clientData, context);
                                break;

                            case (ushort)ClientOpcode.CLIENT_GATEWAY_SHARD_LIST_PING_REQUEST:
                                OnServerListPingRequest(packet, clientData, context);
                                break;

                            case (ushort)ClientOpcode.CLIENT_GATEWAY_SHARD_LIST_REQUEST:
                                OnServerListRequest(packet, clientData, context);
                                break;

                            case (ushort)ClientOpcode.CLIENT_GATEWAY_LOGIN_REQUEST:
                                OnLoginRequest(packet,clientData,context);
                                break;

                            default:
                                break;
                        }
                    }
                }
            }
            catch (Exception)
            {

                throw;
            }


            return true;
            //  throw new NotImplementedException();
        }

        private void OnLoginRequest(Packet packet, ClientData clientData, AsyncContext context)
        {
            clientData.RemoteIpEndPoint = context.State.EndPoint as IPEndPoint;
            ModuleInterface.UserTokenList.Add(clientData);
            var ContentID = packet.ReadByte();

            clientData.Username = packet.ReadAscii();
            clientData.Password = packet.ReadAscii();

            byte result;

            SqlDataReader reader;

            clientData.CertificationManager.Database.Execute(
                $"EXEC dbo._CertifyTB_User @szUserID = '{clientData.Username}',  @szPassword = '{clientData.Md5Password()}'",out reader);

            reader.Read();
            byte.TryParse(reader[0].ToString(),out result);

            Packet ForwardPacketUserChecking = new Packet(0x6008);
            ForwardPacketUserChecking.WriteUInt(ModuleInterface.UserTokenList.IndexOf(clientData));  // forword.id
            ForwardPacketUserChecking.WriteUShort(clientData.CertificationManager.CertificationBody.CertifierID); // Global.bodyid

            if (result == 0)
            {
               clientData.Jid = uint.Parse(reader[1].ToString());
               clientData.SecPrimary = byte.Parse(reader[2].ToString());
               clientData.SecContent = byte.Parse(reader[3].ToString());
               clientData.AccPlayTime = ushort.Parse(reader[4].ToString());
               clientData.LatestUpdateTimeToPlayTime = uint.Parse(reader[5].ToString());

                

                ForwardPacketUserChecking.WriteUShort(0x6200); //inneropcode
                ForwardPacketUserChecking.WriteByteArray(IPAddress.Parse(clientData.RemoteIpEndPoint.Address.ToString()).GetAddressBytes()); //user.ip
                ForwardPacketUserChecking.WriteUInt(clientData.Jid);  // user.jid 
                ForwardPacketUserChecking.WriteByte(ContentID);
                ModuleInterface.ModuleData.SecurityManager.Send(ForwardPacketUserChecking);

            }

            if (result == 1)
            {
                ForwardPacketUserChecking.WriteUShort(0x6111); //inneropcode
                ForwardPacketUserChecking.WriteAscii(clientData.Username);
                ForwardPacketUserChecking.WriteByte(0);
                ModuleInterface.ModuleData.SecurityManager.Send(ForwardPacketUserChecking);

            }

            if (result == 3)
            {
                clientData.Jid = uint.Parse(reader[1].ToString());

            }

            reader.Close();



        }

        private void OnServerListRequest(Packet packet, ClientData clientData, AsyncContext context)
        {
            Packet ackServerList = new Packet((ushort)ServerOpcode.SERVER_GATEWAY_SHARD_LIST_RESPONSE);

            var farm = clientData.CertificationManager.FarmList.SingleOrDefault(p => p.ID >0);
            var shard = clientData.CertificationManager.ShardList.SingleOrDefault(p => p.FarmID == farm.ID);

            ackServerList.WriteBool(true);
            ackServerList.WriteByte(farm.ID);
            ackServerList.WriteAscii(farm.Name);
            ackServerList.WriteBool(false);

            ackServerList.WriteBool(true);
            ackServerList.WriteUShort(shard.ID);
            ackServerList.WriteAscii(shard.Name);
            ackServerList.WriteUShort(500);
            ackServerList.WriteUShort(1000);
            ackServerList.WriteBool(true);
            ackServerList.WriteByte(shard.FarmID);
            ackServerList.WriteBool(false);

            clientData.SecurityManager.Send(ackServerList);
        }

        private void OnServerListPingRequest(Packet packet, ClientData clientData, AsyncContext context)
        {
            var farm = clientData.CertificationManager.FarmList.FirstOrDefault(p => p.ID > 0);
            var machine = clientData.CertificationManager.ServerMachineList.FirstOrDefault(p => p.DivisionID == farm.DivisionID);

            Packet ackServerListPing = new Packet((ushort)ServerOpcode.SERVER_GATEWAY_SHARD_LIST_PING_RESPONSE);
            ackServerListPing.WriteByte(1);
            ackServerListPing.WriteByte(farm.ID);
            ackServerListPing.WriteByteArray(IPAddress.Parse(machine.GetIP(ServerCordBindType.Public)).GetAddressBytes());

            clientData.SecurityManager.Send(ackServerListPing);
        }

        private void OnNoticeRequest(Packet packet, ClientData clientData, AsyncContext context)
        {

            byte contentId = packet.ReadByte();
            var division = clientData.CertificationManager.DivisionList.Any(p => p.ID == contentId);
            if (division)
            {
                //TODO , Send Notices from Account database
                //.....
                Packet ackNotice = new Packet((ushort)ServerOpcode.SERVER_GATEWAY_NOTICE_RESPONSE, false, true);
                ackNotice.WriteByte(clientData.CertificationManager.NoticeList.Count); // notice count
                foreach (var notice in clientData.CertificationManager.NoticeList)
                {
                    ackNotice.WriteAscii(notice.Subject);
                    ackNotice.WriteAscii(notice.Article);
                    ackNotice.WriteDateTime(notice.EditDate);

                }
                clientData.SecurityManager.Send(ackNotice);

            }

        }

        private void OnPatchRequest(Packet packet,ClientData clientData,AsyncContext context)
        {
            Packet ackPatch = new Packet((ushort) ServerOpcode.SERVER_GATEWAY_PATCH_RESPONSE, false, true);


            byte contentId = packet.ReadByte();
            string moduleName = packet.ReadAscii();
            uint version = packet.ReadUInt();

            var content = clientData.CertificationManager.DivisionList.FirstOrDefault(p => p.ID > 0);
            var module = clientData.CertificationManager.ModuleList.Single(p => p.ID == 9);

            if(contentId == content.ID && moduleName == module.Name)
            {

                if (clientData.CertificationManager.CertificationBody.State != ServerBodyState.Blue)
                {
                    ackPatch.WriteByte(0x2); ackPatch.WriteByte(PatchErrorCode.NotInService);
                }

                else if (version > clientData.CertificationManager.ModuleVersions.SingleOrDefault(p => p.nModuleID == 9).nVersion)
                {
                    ackPatch.WriteByte(0x2); ackPatch.WriteByte(PatchErrorCode.InvalidVersion);
                }

                //TODO, else if client update....
                //.....
                else if (version < clientData.CertificationManager.ModuleVersions.SingleOrDefault(p => p.nModuleID == 9).nVersion)
                {
                    ackPatch.WriteByte(0x02);
                    ackPatch.WriteByte(PatchErrorCode.UPDATE);

                    string downloadServerIp = clientData.CertificationManager.CertificationMachine.PublicIP;
                    int downloadServerPort = clientData.CertificationManager.ServerBodyList.SingleOrDefault(p=> p.ModuleID == 3).BindPort;


                    ackPatch.WriteAscii(downloadServerIp);
                    ackPatch.WriteUShort(downloadServerPort);
                    ackPatch.WriteUInt(clientData.CertificationManager.ModuleVersions.SingleOrDefault(p => p.nModuleID == 9).nVersion);

                    SqlDataReader reader;

                    if (clientData.CertificationManager.Database.Execute(
                        $"SELECT nID,szFilename,szPath,nFileSize,nToBePacked FROM dbo._ModuleVersionFile WHERE nValid = 1 AND nModuleID = 9 AND nVersion >{version} ", out reader))
                    {
                        if (reader.HasRows)
                        {

                            while (reader.Read())
                            {
                                var data0 = uint.Parse(reader[0].ToString());
                                var data1 = reader[1].ToString();
                                var data2 = reader[2].ToString();
                                var data3 = uint.Parse(reader[3].ToString());
                                var data4 = uint.Parse(reader[4].ToString()) != 0 ;

                                ackPatch.WriteBool(true);
                                ackPatch.WriteUInt(data0); // nID
                                ackPatch.WriteAscii(data1); //szFilename
                                ackPatch.WriteAscii(data2); //szPath
                                ackPatch.WriteUInt(data3); // nFileSize
                                ackPatch.WriteBool(data4); // nToBePacked
                            }
                        }

                        ackPatch.WriteBool(false);

                    //    clientData.CertificationManager.Version = Convert.ToInt32(reader[0].ToString());
                        reader.Close();


                    }
                }

                else if (version < clientData.CertificationManager.LatestClientVersion)
                {
                    ackPatch.WriteByte(0x2);
                    ackPatch.WriteByte(PatchErrorCode.PatchDisabled);
                }

                else
                {
                    ackPatch.WriteByte(1);
                }



            }
            
            else
            {
                ackPatch.WriteByte(0x2);
                ackPatch.WriteByte(PatchErrorCode.AbnormalModule);
            }

            clientData.SecurityManager.Send(ackPatch);

        }

        public void OnTick(AsyncContext context)
        {

            ClientData clientData = (ClientData)context.User;
            if (clientData == null)
                return;

            if (!clientData.Connected)
                return;

            List<KeyValuePair<TransferBuffer, Packet>> buffers = clientData.SecurityManager.TransferOutgoing();
            if (buffers != null)
            {
                foreach (KeyValuePair<TransferBuffer, Packet> buffer in buffers)
                {
                    //Packet packet = buffer.Value;

                    //byte[] payload = packet.GetBytes();
                    //Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);

                    context.Send(buffer.Key.Buffer, 0, buffer.Key.Size);
                }
            }
            // throw new NotImplementedException();
        }
    }
}
