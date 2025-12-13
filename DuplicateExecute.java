package core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import jakarta.servlet.ServletException;

public class DuplicateExecute {
	
	
	private String broker_path="/opt/tomcat/broker/";
	private String env;
	public DuplicateExecute(String env) {
		
		this.env = env;
	}


	private static String comand2="sh /opt/tomcat/command/duplicate.sh ";
	private List<RestApi>outputLines= Collections.synchronizedList(new ArrayList<RestApi>());
	
	
	public List<RestApi> Execute() throws ServletException, IOException{
		ExecutorService executor=Executors.newFixedThreadPool(16);
		List<Future<Void>> futures=new ArrayList<>();
		Path dir = Paths.get(broker_path+this.env);
		List<String> broker_names = new ArrayList<>();
		try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)){
			for(Path entryPath : stream) {
				if(Files.isRegularFile(entryPath)) {
					broker_names.add(entryPath.getFileName().toString());
				}
			}
		} 
		for(String broker:broker_names) {
			Callable<Void> task = () -> {
				try {
					String cmd=comand2+"/opt/tomcat/broker/"+this.env+"/"+broker;
					System.out.println(cmd);
					ProcessBuilder builder = new ProcessBuilder("/bin/bash", "-lc", cmd);
					builder.redirectErrorStream(true);
		            Process process = builder.start();
		            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
		            String line;
					while((line=reader.readLine())!=null) {
						String [] parts=line.trim().split("\\s+", 5);
						if(parts.length>=6) {
							String ip=parts[0];
							String node=parts[1];
							String server=parts[2];
							String apiName=parts[3];
							String state=parts[4];
							String DeployedDate=parts[5];
							RestApi RA=new RestApi(apiName, node, server,ip, state,DeployedDate);
							System.out.println(RA.toString());
							outputLines.add(RA);
						}
		            }
					@SuppressWarnings("unused")
					int exitcode=process.waitFor();
		            return null;
				} catch (Exception e) {
					System.out.println(e.getMessage());
					return null;
				}
			};
			futures.add(executor.submit(task));
		}
		
		executor.shutdown();try {
			executor.awaitTermination(60, TimeUnit.SECONDS);
		} catch (InterruptedException e2) {
			throw new ServletException("Task Interupted"+e2.getMessage());
		}
		
		return outputLines;
	}

}
