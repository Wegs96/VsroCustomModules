using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Threading;
using NLog;
using Replace.Common;
using Replace.Common.AsyncNetwork;
using Replace.Common.Certification;
using Replace.Common.Security;

namespace GatewayServer
{
    internal class ModuleInterface : IAsyncInterface
    {
        private static Logger logger = LogManager.GetLogger("GatewayServer"/*nameof(ModuleInterface)*/);

        public bool OnConnect(AsyncContext context)
        {
         //   logger.Debug(nameof(this.OnConnect));

            ModuleData moduleData = new ModuleData();
            moduleData.CertificationManager = context.User as CertificationManager;
            moduleData.Connected = true;

            context.User = moduleData;

           
            return true;


          //  throw new NotImplementedException();
        }

        public void OnDisconnect(AsyncContext context)
        {
            logger.Debug(nameof(this.OnDisconnect));

            throw new NotImplementedException();
        }

        public void OnError(AsyncContext context, object user)
        {
            logger.Debug(nameof(this.OnError));

            throw new NotImplementedException();
        }

        public bool OnReceive(AsyncContext context, byte[] buffer, int count)
        {
           // logger.Debug(nameof(this.OnReceive));

            ModuleData moduleData = (ModuleData)context.User;


            try
            {
                moduleData.SecurityManager.Recv(buffer, 0, count);
                List<Packet> packets = moduleData.SecurityManager.TransferIncoming();

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
                                logger.Info("request server certification");
                                OnModuleIdentification(packet, moduleData, context);
                                break;

                            case 0x2005:
                                OnServerUpdate(packet, moduleData,context);
                                break;

                            case 0x6005:
                                OnServerUpdateRequest(packet, moduleData,context);
                                break;

                            case 0xA003:
                                logger.Info("successfully server certificate"); /*successfully server certificated*/
                                OnCertificationResponse(packet, moduleData, context);
                                break;

                            case 0x6008:
                                OnForwardRequest(packet, moduleData);
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

        private void OnServerUpdateRequest(Packet packet, ModuleData context_data,AsyncContext context)
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

                    var bodyID = packet.ReadUShort();

                    serverUpdate.WriteUShort(bodyID/*body.ID*/);
                    serverUpdate.WriteUInt(ServerBodyState.Cert/*body.State*/);

                }

                context_data.SecurityManager.Send(serverUpdate);
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

                    var cordID = packet.ReadUInt();

                    serverUpdate.WriteUInt(cordID/*cord.ID*/);
                    serverUpdate.WriteUInt(ServerCordState.Blind/*cord.State*/);

                }

                context_data.SecurityManager.Send(serverUpdate);
            }
        }

        private void OnForwardRequest(Packet packet, ModuleData context_data)
        {
            var forwardingID = packet.ReadUInt();
            var forwardingDestination = packet.ReadUShort(); //ServerBodyID
            var forwardedOpcode = packet.ReadUShort();

            var forwardAck = new Packet(0xA008, packet.Encrypted, packet.Massive);

            var result = forwardingDestination == context_data.CertificationManager.CertificationBody.ID;
            if (result)
            {
                forwardAck.WriteByte(1); //result
                forwardAck.WriteUInt(forwardingID);
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
                        serverUpdate.WriteUShort(context_data.CertificationManager.CertificationBody.ID);
                        serverUpdate.WriteByte(ServerBodyState.Blue);
                        serverUpdate.WriteByte(0x00);
                        serverUpdate.WriteByte(0x00);
                        serverUpdate.WriteByte(0x00);
                        serverUpdate.WriteUInt(ServerCordState.Established);

                        context_data.SecurityManager.Send(serverUpdate);


                        forwardAck.WriteUShort(0xA303);
                        forwardAck.WriteByte(0x01);
                        forwardAck.WriteByte(0x00);
                        forwardAck.WriteByte(0x01);

                        context_data.CertificationManager.CertificationBody.State = ServerBodyState.Blue;
                        break;

                    default:
                        logger.Warn($"Unknown forwardedOpcode [{forwardedOpcode.ToString("X4")}]: {packet}");
                        break;
                }
            }
            else
            {
                //return;
                //Lost the sample -.-
                forwardAck.WriteByte(2); //result
                forwardAck.WriteUInt(forwardingID);
                forwardAck.WriteUShort(0); //errorCode?
            }
            context_data.SecurityManager.Send(forwardAck);
        }

        private void OnCertificationResponse(Packet packet, ModuleData moduleData, AsyncContext context)
        {
            var cert = moduleData.CertificationManager;
            //byte[] payload = packet.GetBytes();
            //   Console.WriteLine("[{7}][{0:X4}][{1} bytes]{2}{3}{4}{5}{6}", packet.Opcode, payload.Length, packet.Encrypted ? "[Encrypted]" : "", packet.Massive ? "[Massive]" : "", Environment.NewLine, payload.HexDump(), Environment.NewLine, context.Guid);

            packet.ReadByte();
            cert.ReadAcknowledge(packet);


            logger.Fatal($"server cord established : {ServerUpdateType.Cord} ({context.State.EndPoint})");


            #region connection
            string[] certCon =
                moduleData.CertificationManager.CertificationDivision.DBConfig.Split(';');

            string ConnectionString =
                $"Data Source={certCon[1].Substring(certCon[1].IndexOf('=') + 1)};Initial Catalog={certCon[5].Substring(certCon[5].IndexOf('=') + 1)};User ID={certCon[3].Substring(certCon[3].IndexOf('=') + 1)};Password={certCon[4].Substring(certCon[4].IndexOf('=') + 1)}";

            moduleData.CertificationManager.Database.Open(
                moduleData.CertificationManager.Config.CertificationConnectionString =
                    ConnectionString);

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
        }


        private void DatabaseLoadVersion(ModuleData moduleData)
        {


            SqlDataReader reader;

            if (moduleData.CertificationManager.Database.Execute(
                "SELECT TOP 1 nVersion FROM _ModuleVersion WHERE nModuleID = 9 AND nValid = 1", out reader))
            {
                reader.Read();
                moduleData.CertificationManager.Version = Convert.ToInt32(reader[0].ToString());
                reader.Close();
                logger.Info($"Current Client Version : {moduleData.CertificationManager.Version}");

            }

        }

        private void DatabaseLoadNews(ModuleData moduleData)
        {


            SqlDataReader reader;


            if (moduleData.CertificationManager.Database.Execute("SELECT Subject, Article,EditDate FROM _Notice ORDER BY ID DESC", out reader))
                moduleData.CertificationManager.Load(reader, moduleData.CertificationManager.NoticeList);

            logger.Info($"article loaded : {moduleData.CertificationManager.NoticeList.Count}");
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

                    var serverBodyID = packet.ReadUShort();
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

                    var serverCordID = packet.ReadUInt();
                    var serverCordState = (ServerCordState)packet.ReadUInt();

                }

            }

        }

        public void OnTick(AsyncContext context)
        {
          //  logger.Debug(nameof(this.OnTick));

            ModuleData moduleData = (ModuleData)context.User;
            if (moduleData == null)
                return;

            if (!moduleData.Connected)
                return;

            List<KeyValuePair<TransferBuffer, Packet>> buffers = moduleData.SecurityManager.TransferOutgoing();
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
