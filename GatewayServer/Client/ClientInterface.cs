using NLog;
using Replace.Common;
using Replace.Common.AsyncNetwork;
using Replace.Common.Certification;
using Replace.Common.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using Replace.Common.Gateway;

namespace GatewayServer
{
    internal class ClientInterface : IAsyncInterface
    {
        private static Logger logger = LogManager.GetLogger(nameof(ClientInterface));

        public bool OnConnect(AsyncContext context)
        {

            ClientData clientData = new ClientData();
            clientData.Connected = true;
            clientData.CertificationManager = context.User as CertificationManager;

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

        private void OnServerListRequest(Packet packet, ClientData clientData, AsyncContext context)
        {
            Packet AckServerList = new Packet((ushort)ServerOpcode.SERVER_GATEWAY_SHARD_LIST_RESPONSE);

            var Farm = clientData.CertificationManager.FarmList.SingleOrDefault(p => p.ID >0);
            var Shard = clientData.CertificationManager.ShardList.SingleOrDefault(p => p.FarmID == Farm.ID);

            AckServerList.WriteBool(true);
            AckServerList.WriteByte(Farm.ID);
            AckServerList.WriteAscii(Farm.Name);
            AckServerList.WriteBool(false);

            AckServerList.WriteBool(true);
            AckServerList.WriteUShort(Shard.ID);
            AckServerList.WriteAscii(Shard.Name);
            AckServerList.WriteUShort(500);
            AckServerList.WriteUShort(1000);
            AckServerList.WriteBool(false);
            AckServerList.WriteByte(Shard.FarmID);
            AckServerList.WriteBool(false);

            clientData.SecurityManager.Send(AckServerList);
        }

        private void OnServerListPingRequest(Packet packet, ClientData clientData, AsyncContext context)
        {
            var Farm = clientData.CertificationManager.FarmList.FirstOrDefault(p => p.ID > 0);
            var Machine = clientData.CertificationManager.ServerMachineList.FirstOrDefault(p => p.DivisionID == Farm.DivisionID);

            Packet AckServerListPing = new Packet((ushort)ServerOpcode.SERVER_GATEWAY_SHARD_LIST_PING_RESPONSE);
            AckServerListPing.WriteByte(1);
            AckServerListPing.WriteByte(Farm.ID);
            AckServerListPing.WriteByteArray(IPAddress.Parse(Machine.GetIP(ServerCordBindType.Public)).GetAddressBytes());

            clientData.SecurityManager.Send(AckServerListPing);
        }

        private void OnNoticeRequest(Packet packet, ClientData clientData, AsyncContext context)
        {

            byte ContentID = packet.ReadByte();
            var Division = clientData.CertificationManager.DivisionList.Any(p => p.ID == ContentID);
            if (Division)
            {
                //TODO , Send Notices from Account database
                //.....
                Packet AckNotice = new Packet((ushort)ServerOpcode.SERVER_GATEWAY_NOTICE_RESPONSE, false, true);
                AckNotice.WriteByte(clientData.CertificationManager.NoticeList.Count); // notice count
                foreach (var notice in clientData.CertificationManager.NoticeList)
                {
                    AckNotice.WriteAscii(notice.Subject);
                    AckNotice.WriteAscii(notice.Article);
                    AckNotice.WriteDateTime(notice.EditDate);

                }
                clientData.SecurityManager.Send(AckNotice);

            }

        }

        private void OnPatchRequest(Packet packet,ClientData clientData,AsyncContext context)
        {
            Packet AckPatch = new Packet((ushort) ServerOpcode.SERVER_GATEWAY_PATCH_RESPONSE, false, true);


            byte ContentID = packet.ReadByte();
            string ModuleName = packet.ReadAscii();
            uint Version = packet.ReadUInt();

            var Content = clientData.CertificationManager.DivisionList.FirstOrDefault(p => p.ID > 0);
            var Module = clientData.CertificationManager.ModuleList.Single(p => p.ID == 9);

            if(ContentID == Content.ID && ModuleName == Module.Name)
            {

                if (clientData.CertificationManager.CertificationBody.State != ServerBodyState.Blue)
                {
                    AckPatch.WriteByte(0x2); AckPatch.WriteByte(PatchErrorCode.NotInService);
                }

                else if (Version > clientData.CertificationManager.Version)
                {
                    AckPatch.WriteByte(0x2); AckPatch.WriteByte(PatchErrorCode.InvalidVersion);
                }

                //TODO, else if client update....
                //.....

                else if (Version < clientData.CertificationManager.LatestClientVersion)
                {
                    AckPatch.WriteByte(0x2); AckPatch.WriteByte(PatchErrorCode.PatchDisabled);
                }

                else
                {
                    AckPatch.WriteByte(1);
                }



            }
            
            else
            {
                AckPatch.WriteByte(0x2);
                AckPatch.WriteByte(PatchErrorCode.AbnormalModule);
            }

            clientData.SecurityManager.Send(AckPatch);

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
                    Packet packet = buffer.Value;

                    //byte[] payload = packet.GetBytes();
                    //Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);

                    context.Send(buffer.Key.Buffer, 0, buffer.Key.Size);
                }
            }
            // throw new NotImplementedException();
        }
    }
}
