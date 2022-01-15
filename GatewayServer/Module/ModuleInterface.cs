using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using GatewayServer.Client;
using GatewayServer.Module.Config;
using NLog;
using Replace.Common;
using Replace.Common.AsyncNetwork;
using Replace.Common.Certification;
using Replace.Common.Gateway;
using Replace.Common.Security;

namespace GatewayServer.Module
{
    internal class ModuleInterface : IAsyncInterface
    {
        private static Logger _logger = LogManager.GetLogger("GatewayServer"/*nameof(ModuleInterface)*/);
        public static ModuleData ModuleData;
        public static List<ClientData> UserTokenList = new List<ClientData>();
        public bool OnConnect(AsyncContext context)
        {
         //   logger.Debug(nameof(this.OnConnect));

            /*ModuleData*/ ModuleData = new ModuleData();
            ModuleData.CertificationManager = context.User as CertificationManager;
            ModuleData.Connected = true;

            context.User = ModuleData;

           
            return true;


          //  throw new NotImplementedException();
        }

        public void OnDisconnect(AsyncContext context)
        {
            _logger.Debug(nameof(this.OnDisconnect));

            throw new NotImplementedException();
        }

        public void OnError(AsyncContext context, object user)
        {
            _logger.Debug(nameof(this.OnError));

            throw new NotImplementedException();
        }

        public bool OnReceive(AsyncContext context, byte[] buffer, int count)
        {
            // logger.Debug(nameof(this.OnReceive));

            /*ModuleData*/
            //moduleData = (ModuleData)context.User;


            try
            {
                ModuleData.SecurityManager.Recv(buffer, 0, count);
                List<Packet> packets = ModuleData.SecurityManager.TransferIncoming();

                if(packets != null)
                {
                    foreach (Packet packet in packets)
                    {
//#if DEBUG
//                        byte[] payload = packet.GetBytes();
//                        Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);
//#endif
                        switch (packet.Opcode)
                        {
                            case 0x5000:
                            case 0x9000:
                                continue;

                            case 0x2001:
                                _logger.Info("request server certification");
                                OnModuleIdentification(packet, ModuleData, context);
                                break;

                            case 0x2005:
                                OnServerUpdate(packet, ModuleData,context);
                                break;

                            case 0x6005:
                                OnServerUpdateRequest(packet, ModuleData,context);
                                break;

                            case 0xA003:
                                _logger.Info("successfully server certificate"); /*successfully server certificated*/
                                OnCertificationResponse(packet, ModuleData, context);
                                break;

                            case 0x6008:
                                OnForwardRequest(packet, ModuleData);
                                break;
                            case 0xA008:
                                OnForwardRes(packet, ModuleData);
                                break;
                            default:
                                //Console.WriteLine();
                                //byte[] payload = packet.GetBytes();
                                //Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);
                                break;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return false;
                throw;
            }

            return true;
                

            //throw new NotImplementedException();
        }

        private void Ping(object obj)
        {
            ModuleData moduleData = (ModuleData)obj;
            while (true)
            {
                Packet ping = new Packet(0x2002);
                moduleData.SecurityManager.Send(ping);

                Thread.Sleep(5000);
            }
        }

        private void OnModuleIdentification(Packet packet,ModuleData moduleData,AsyncContext context)
        {

                Packet ack = new Packet(0x6003);
                ack.WriteAscii("GatewayServer");
                ack.WriteAscii("10.0.0.100");
                moduleData.SecurityManager.Send(ack);

                Thread ping = new Thread(Ping);
                ping.Start(moduleData);

        }

        private void OnServerUpdateRequest(Packet packet, ModuleData contextData,AsyncContext context)
        {
            var updateFlag = (ServerUpdateType)packet.ReadByte();
            if (updateFlag.HasFlags(ServerUpdateType.Body))
            {
                var serverUpdate = new Packet(0x2005, false, true);
                serverUpdate.WriteByte(ServerUpdateType.Body);

                var unkByte0 = packet.ReadByte(); //checkByte = 0
                serverUpdate.WriteByte(unkByte0);
                while (true)
                {
                    var entryFlag = packet.ReadByte();
                    serverUpdate.WriteByte(entryFlag);
                    if (entryFlag == 2)
                        break;

                    var bodyId = packet.ReadUShort();

                    serverUpdate.WriteUShort(bodyId/*body.ID*/);
                    serverUpdate.WriteUInt(ServerBodyState.Cert/*body.State*/);

                }

                contextData.SecurityManager.Send(serverUpdate);
            }
            if (updateFlag.HasFlags(ServerUpdateType.Cord))
            {
                var serverUpdate = new Packet(0x2005, false, true);
                serverUpdate.WriteByte(ServerUpdateType.Cord);

                var unkByte0 = packet.ReadByte(); //checkByte = 0
                serverUpdate.WriteByte(unkByte0);
                while (true)
                {
                    var entryFlag = packet.ReadByte();
                    serverUpdate.WriteByte(entryFlag);
                    if (entryFlag == 2)
                        break;

                    var cordId = packet.ReadUInt();

                    serverUpdate.WriteUInt(cordId/*cord.ID*/);
                    serverUpdate.WriteUInt(ServerCordState.Blind/*cord.State*/);

                }

                contextData.SecurityManager.Send(serverUpdate);
            }
        }
        private void OnForwardRes(Packet packet, ModuleData moduleData)
        {
            var result = packet.ReadByte();
            if (result == 1)
            {
                var forwardingId = packet.ReadUInt();
                var forwardedOpcode = packet.ReadUShort();

                var clientData = UserTokenList[(int)forwardingId];
                var AgentBody = clientData.CertificationManager.ServerBodyList.SingleOrDefault(p => p.ModuleID == 6);

                if (forwardedOpcode == 0xA203)
                {

                    packet.ReadByte();
                    clientData.AgentToken = packet.ReadUInt(); // agent token

                    var LoginAck = new Packet(0xA102, true);
                    LoginAck.WriteByte(1);
                    LoginAck.WriteUInt(clientData.AgentToken);

                    LoginAck.WriteAscii(clientData.CertificationManager.CertificationMachine.PublicIP);
                    LoginAck.WriteUShort(AgentBody.BindPort);

                    clientData.SecurityManager.Send(LoginAck);
                }

                if (forwardedOpcode == 0xA200)

                {
                    packet.ReadUInt();
                    var loginResult = packet.ReadByte();

                    if (loginResult != 1)
                    {
                        if (loginResult == 2 && packet.ReadByte() == 1)
                        {
                            var LoginAck = new Packet(0xA102, true);
                            LoginAck.WriteByte(2);
                            LoginAck.WriteUInt(LoginErrorCode.AlreadyConnected);
                            clientData.SecurityManager.Send(LoginAck);
                        }
                    }
                    else
                    {
                        Packet ForwardPacket = new Packet(0x6008);
                        ForwardPacket.WriteUInt(ModuleInterface.UserTokenList.IndexOf(clientData)); // forword.id
                        ForwardPacket.WriteUShort(AgentBody.ID); // agent.bodyid
                        ForwardPacket.WriteUShort(0x6203); //inneropcode


                        ForwardPacket.WriteByteArray(IPAddress.Parse(clientData.RemoteIpEndPoint.Address.ToString())
                            .GetAddressBytes()); //user.ip

                        ForwardPacket.WriteAscii(clientData.Username); //username
                        ForwardPacket.WriteAscii(clientData.Password); //password
                        ForwardPacket.WriteUInt(clientData.Jid); // userjid
                        ForwardPacket.WriteByte(clientData.SecPrimary); //sec_primary
                        ForwardPacket.WriteByte(clientData.SecContent); //sec_content
                        ForwardPacket.WriteUShort(clientData.AccPlayTime); // AccPlayTime
                        ForwardPacket.WriteUInt(clientData.LatestUpdateTimeToPlayTime); //LatestUpdateTime_ToPlayTime


                        moduleData.SecurityManager.Send(ForwardPacket);
                    }
                }

                if (forwardedOpcode == 0xA111)
                {
                    packet.ReadAscii(); // username
                    packet.ReadUShort();
                    uint maxFail = packet.ReadUInt();
                    uint curFail = packet.ReadUInt();

                    var LoginAck = new Packet(0xA102, true);

                    LoginAck.WriteByte(2);
                    LoginAck.WriteByte(LoginErrorCode.InvalidCredentials);
                    LoginAck.WriteUInt(maxFail);
                    LoginAck.WriteUInt(curFail);

                    clientData.SecurityManager.Send(LoginAck);

                    Task.Delay(1000);
                    if(curFail >= maxFail)
                        clientData.Context.State.Context.Disconnect();
                }

            }
          
        }

        private void OnForwardRequest(Packet packet, ModuleData contextData)
        {
            var forwardingId = packet.ReadUInt();
            var forwardingDestination = packet.ReadUShort(); //ServerBodyID
            var forwardedOpcode = packet.ReadUShort();

            var forwardAck = new Packet(0xA008, packet.Encrypted, packet.Massive);

            var result = forwardingDestination == contextData.CertificationManager.CertificationBody.ID;
            if (result)
            {
                forwardAck.WriteByte(1); //result
                forwardAck.WriteUInt(forwardingId);
                switch (forwardedOpcode)
                {
                    case 0x6300: //ms ping
                        forwardAck.WriteUShort(0xA300);
                        forwardAck.WriteByte(0x1);
                        break;

                    case 0x6303://Status Update

                        Packet serverUpdate = new Packet(0x2005, false, true);
                        serverUpdate.WriteByte(ServerUpdateType.Body);

                        serverUpdate.WriteByte(0x00);
                        serverUpdate.WriteByte(0x01);
                        serverUpdate.WriteUShort(contextData.CertificationManager.CertificationBody.ID);
                        serverUpdate.WriteByte(ServerBodyState.Blue);
                        serverUpdate.WriteByte(0x00);
                        serverUpdate.WriteByte(0x00);
                        serverUpdate.WriteByte(0x00);
                        serverUpdate.WriteUInt(ServerCordState.Established);

                        contextData.SecurityManager.Send(serverUpdate);


                        forwardAck.WriteUShort(0xA303);
                        forwardAck.WriteByte(0x01);
                        forwardAck.WriteByte(0x00);
                        forwardAck.WriteByte(0x01);

                        contextData.CertificationManager.CertificationBody.State = ServerBodyState.Blue;
                        break;

                    default:
                        _logger.Warn($"Unknown forwardedOpcode [{forwardedOpcode.ToString("X4")}]: {packet}");
                        break;
                }
            }
            else
            {
                //return;
                //Lost the sample -.-
                forwardAck.WriteByte(2); //result
                forwardAck.WriteUInt(forwardingId);
                forwardAck.WriteUShort(0); //errorCode?
            }
            contextData.SecurityManager.Send(forwardAck);
        }

        private void OnCertificationResponse(Packet packet, ModuleData moduleData, AsyncContext context)
        {
            var cert = moduleData.CertificationManager;
            //byte[] payload = packet.GetBytes();
            //   Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);

            packet.ReadByte();
            cert.ReadAcknowledge(packet);


            _logger.Fatal($"server cord established : {ServerUpdateType.Cord} ({context.State.EndPoint})");


            #region connection
            string[] certCon =
                moduleData.CertificationManager.CertificationDivision.DBConfig.Split(';');

            string connectionString =
                $"Data Source={certCon[1].Substring(certCon[1].IndexOf('=') + 1)};Initial Catalog={certCon[5].Substring(certCon[5].IndexOf('=') + 1)};User ID={certCon[3].Substring(certCon[3].IndexOf('=') + 1)};Password={certCon[4].Substring(certCon[4].IndexOf('=') + 1)}";

            moduleData.CertificationManager.Database.Open(
                moduleData.CertificationManager.Config.CertificationConnectionString =
                    connectionString);

            #endregion


            DatabaseLoadVersion(moduleData);
            DatabaseLoadNews(moduleData);


            var serverUpdate = new Packet(0x2005, false, true);
            serverUpdate.WriteByte(ServerUpdateType.Body);
            serverUpdate.WriteByte(0);

            serverUpdate.WriteByte(1);

            serverUpdate.WriteUShort(moduleData.CertificationManager.CertificationBody.ID);
            serverUpdate.WriteUInt(ServerBodyState.Gray/*body.State*/);
            serverUpdate.WriteByte(2);

            moduleData.SecurityManager.Send(serverUpdate);


            Program.AsyncServer = new AsyncServer();
            Program.AsyncServer.Accept(moduleData.CertificationManager.CertificationMachine.PublicIP, moduleData.CertificationManager.CertificationBody.BindPort, 5, new ClientInterface(), moduleData.CertificationManager);
            Program.Certificated = true;
        }

        private void DatabaseLoadVersion(ModuleData moduleData)
        {

            try
            {

                SqlDataReader reader;

                #region Load ModuleVersion

                if (moduleData.CertificationManager.Database.Execute(
                    "select * from _ModuleVersion with (NOLOCK) where nValid = 1", out reader))
                {
                    while (reader.Read())
                    {
                        var moduleVersion = new ModuleVersion();

                        moduleVersion.nID = uint.Parse(reader["nID"].ToString());
                        moduleVersion.nDivisionID = byte.Parse(reader["nDivisionID"].ToString());
                        moduleVersion.nContentID = byte.Parse(reader["nContentID"].ToString());
                        moduleVersion.nModuleID = byte.Parse(reader["nModuleID"].ToString());
                        moduleVersion.nVersion = uint.Parse(reader["nVersion"].ToString());
                        moduleVersion.szVersion = reader["szVersion"].ToString();
                        moduleVersion.szDesc = reader["szDesc"].ToString();
                        moduleVersion.nValid = byte.Parse(reader["nValid"].ToString());
                        

                        moduleData.CertificationManager.ModuleVersions.Add(moduleVersion);
                    }
                    reader.Close();
                    _logger.Info($"Current Client Version : {moduleData.CertificationManager.ModuleVersions.SingleOrDefault(p => p.nModuleID == 9).nVersion}");

                    #endregion
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

        }

        private void DatabaseLoadNews(ModuleData moduleData)
        {


            SqlDataReader reader;


            if (moduleData.CertificationManager.Database.Execute("SELECT top 4 Subject, Article,EditDate FROM _Notice ORDER BY ID DESC", out reader))
                moduleData.CertificationManager.Load(reader, moduleData.CertificationManager.NoticeList);

            _logger.Info($"article loaded : {moduleData.CertificationManager.NoticeList.Count}");
        }

        private void OnServerUpdate(Packet packet, ModuleData moduleData , AsyncContext context)
        {
            var updateType = (ServerUpdateType)packet.ReadByte();

            if (updateType.HasFlags(ServerUpdateType.Body))
            {
                //ServerBody
                var unkByte0 = packet.ReadByte(); //checkByte = 0
                while (true)
                {
                    var entryFlag = packet.ReadByte();
                    if (entryFlag == 2)
                        break;

                    var serverBodyId = packet.ReadUShort();
                    var serverBodyState = (ServerBodyState)packet.ReadUInt();

                  //  logger.Info($"Add ServerNotify : ({moduleData.CertificationManager.CertificationBody.MachineID.}) - GlobalManager");


                }
            }

            if (updateType.HasFlags(ServerUpdateType.Cord))
            {
                //ServerCord
                var unkByte0 = packet.ReadByte(); //check byte = 0
                while (true)
                {
                    var entryFlag = packet.ReadByte();
                    if (entryFlag == 2)
                        break;

                    var serverCordId = packet.ReadUInt();
                    var serverCordState = (ServerCordState)packet.ReadUInt();

                }

            }

        }

        public void OnTick(AsyncContext context)
        {
          //  logger.Debug(nameof(this.OnTick));

            //ModuleData moduleData = (ModuleData)context.User;
            if (ModuleData == null)
                return;

            if (!ModuleData.Connected)
                return;

            List<KeyValuePair<TransferBuffer, Packet>> buffers = ModuleData.SecurityManager.TransferOutgoing();
            if (buffers != null)
            {
                foreach (KeyValuePair<TransferBuffer, Packet> buffer in buffers)
                {
//#if DEBUG
//                    Packet packet = buffer.Value;

//                    byte[] payload = packet.GetBytes();
//                    Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);
//#endif
                    context.Send(buffer.Key.Buffer, 0, buffer.Key.Size);
                }
            }
            //throw new NotImplementedException();
        }
    }
}
