/*--------------------------------------------------------

1. Name / Date: Marija Jovicic/May 22th,2021

2. Java version used (java -version), if not the official version for the class: build 14.0.1+7

3. Precise command-line compilation examples / instructions:

> javac -cp "gson-2.8.2.jar" Blockchain.java

In three different tabs:
> java -cp ".:gson-2.8.2.jar" Blockchain 0
> java -cp ".:gson-2.8.2.jar" Blockchain 1
> java -cp ".:gson-2.8.2.jar" Blockchain 2

4. Precise examples / instructions to run this program:
In separate shell windows:

In three different tabs:
> java -cp ".:gson-2.8.2.jar" Blockchain 0
> java -cp ".:gson-2.8.2.jar" Blockchain 1
> java -cp ".:gson-2.8.2.jar" Blockchain 2

Or run:
> osascript runProcesses.scpt
//Adjust the script based on the location of the project!

5. List of files needed for running the program.
Blockchain.java

5. Notes:

----------------------------------------------------------*/

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.awt.*;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class Blockchain {
    //GUI Frame
    static JFrame frame;
    static JPanel panel = new JPanel();
    static int counter = 1; //for counting the block number
    static LinkedList<Block> linkedList = new LinkedList<>(); //store verified blocks from all processes here
    static HashMap<Integer, String> publicKeys = new HashMap<>(); //store all public keys along with pids from all processes that are competing
    final static int numOfDataFiles = 3; //store the number of txt files you want to read the data from
    final static int expectedRecords = 12;
    static int N = 1; //for keeping track of the number of blocks
    static String prevBlockHash; //for making sure we know what the previous block's hash is
    static int processNum; //store the process id here
    static KeyPair keys; //store the public/private key pair for this process here

    static int UnverifiedBlockPort = 4820; //port that receives unverified blocks
    static int BlockchainPort = 4930; //port that updates the blockchain
    static int PublicKeyPort = 4710; //port that receives public keys

    public static Comparator<Block> BlockTSComparator = (b1, b2) -> { //define a custom Comparator for our Blocks, based on the time they have been read (used in Priority Queue)
        String s1 = b1.getTimeStamp(); //get the timestamp of the first passed in block
        String s2 = b2.getTimeStamp(); //get the timestamp of the second passed in block
        if (s1 == s2) { //if they are completely the same, then return 0
            return 0;
        }
        if (s1 == null) { //if the first timestamp is null then return -1 and consider the second one to be greater
            return -1;
        }
        if (s2 == null) { //if the second timestamp is null then return 1 and consider the first one to be greater
            return 1;
        }
        return s1.compareTo(s2); //if they are not null or equal then compare these Strings using the built in Strings comparator
    };

    static Queue<Block> pq = new PriorityQueue<>(expectedRecords, BlockTSComparator); //store unverified blocks from all processes here

    public Blockchain() throws Exception { //constructor
        prevBlockHash = generateRandomString(); //generate a dummy first hash
        Random rand = new Random(); //create a Random object
        keys = generateKeyPair(rand.nextLong()); //create and store the key pair based on a random seed
    }

    static class Block { //inner class for Blocks in the Blockchain
        int blockID; //used for numbering the Blocks in order they are placed into the blockchain
        String timeStamp; //stores the time when the block was created from a file
        String uuid; //unique identifier for every block to make sure that there are no same 2 blocks
        int verificationProcessID; //stores the pid that solved the puzzle for this block
        String firstName; //first name record
        String lastName; //last name record
        String DOB; //date of birth
        String phoneNum; //patient's phone number
        String diagnosis; //patient's diagnosis
        String treatment; //recommended treatment
        String med; //recommended medicine
        String randSeed; // the random seed/String we have used to solve the puzzle
        String winningHash; //unsigned hash that was generated based on the winning random seed
        String signedSHA256; //signed winning hash

        public String getSignedSHA256() {
            return signedSHA256;
        } //getter for signed winning hash

        public void setSignedSHA256(String SHA) {
            signedSHA256 = SHA;
        } //setter for signed winning hash

        public int getBlockID() {
            return blockID;
        } //getter for block id

        public void setBlockID(int blockID) {
            this.blockID = blockID;
        } //setter for block id

        public int getVerificationProcessID() {
            return verificationProcessID;
        } //getter for winner pid

        public void setVerificationProcessID(int verificationProcessID) { this.verificationProcessID = verificationProcessID; } //setter for winner pid

        public String getUUID() { return uuid; } //getter for uuid

        public void setUUID(String uuid) {
            this.uuid = uuid;
        } //setter for uuid

        public String getLastName() {
            return lastName;
        } //getter for last name

        public void setLastName(String lastName) {
            this.lastName = lastName;
        } //setter for last name

        public String getFirstName() {
            return firstName;
        } //getter for first name

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        } //setter for first name

        public String getDOB() {
            return DOB;
        } //getter for dob

        public void setDOB(String RS) {
            this.DOB = RS;
        } //setter for dob

        public String getPhoneNum() {
            return phoneNum;
        } //getter for phone number

        public void setPhoneNum(String phoneNum) {
            this.phoneNum = phoneNum;
        } //setter for phone number

        public String getDiagnosis() {
            return diagnosis;
        } //getter for diagnosis

        public void setDiagnosis(String diagnosis) {
            this.diagnosis = diagnosis;
        } //setter for diagnosis

        public String getTreatment() {
            return treatment;
        } //setter for treatment

        public void setTreatment(String treatment) {
            this.treatment = treatment;
        } //setter for treatment

        public String getMed() {
            return med;
        } //getter for medicine

        public void setMed(String med) {
            this.med = med;
        } //setter for medicine

        public String getRandomSeed() { return randSeed; } //getter for random seed

        public void setRandomSeed(String randSeed) {
            this.randSeed = randSeed;
        } //setter for random seed

        public String getWinningHash() {
            return winningHash;
        } //getter for winning hash

        public void setWinningHash(String winningHash) {
            this.winningHash = winningHash;
        } //setter for winning hash

        public String getTimeStamp() {
            return timeStamp;
        } //getter for timestamp

        public void setTimeStamp(String timeStamp) {
            this.timeStamp = timeStamp;
        } //setter for timestamp
    }

    public static void main(String[] args) throws Exception { //start execution of a process
        if (args.length < 1) processNum = 0; //if there are no arguments set pid to 0
        else if (args[0].equals("0")) processNum = 0; //if argument is 0, set pid to 0
        else if (args[0].equals("1")) processNum = 1; //if argument is 1, set pid to 1
        else if (args[0].equals("2")) processNum = 2; //if argument is 2, set pid to 2
        else processNum = 0; //if argument is something else, set pid to 0

        UnverifiedBlockPort = UnverifiedBlockPort + processNum; //port that receives unverified blocks
        BlockchainPort = BlockchainPort + processNum; //port that receives updated Blockchains
        PublicKeyPort = PublicKeyPort + processNum; //port that receives public keys

        System.out.println("Hello from process: " + processNum); //print out the pid on the console

        Blockchain bc = new Blockchain(); //create a new instance of a blockchain
        String file = switch (processNum) {//depending on the pid, read the corresponding file
            case 1 -> "BlockInput1.txt"; //process 1
            case 2 -> "BlockInput2.txt"; //process 2
            default -> "BlockInput0.txt"; //process 0 or anything else
        };

        UnverifiedBlockLooper ubl = new UnverifiedBlockLooper(UnverifiedBlockPort); //create a server that will receive unverified blocks from all processes
        Thread t = new Thread(ubl); //create an async thread that will act as a server
        t.start(); //start the server

        PublicKeyLooper pkl = new PublicKeyLooper(PublicKeyPort); //create a server that will receive public keys from all processes
        Thread t1 = new Thread(pkl); //create an async thread that will act as a server
        t1.start(); //start the server

        BlockchainLooper bcl = new BlockchainLooper(BlockchainPort); //create a server that will receive public keys from all processes
        Thread t2 = new Thread(bcl); //create an async thread that will act as a server
        t2.start();  //start the server

        Starter s = new Starter(3000+processNum); //create a new class that will trigger other processes to start after process 2 is running
        Thread tS = new Thread(s); //new thread that will receive the signal form process 2
        tS.start(); //start the thread

        if(processNum==2){ //if the process num is 2 then we will send the signal to all other processes
            //start the gui
            Blockchain.frame = new JFrame("Blockchain");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(1500,500);
            Blockchain.frame.setVisible(true);
            Blockchain.frame.getContentPane().add(BorderLayout.CENTER, Blockchain.panel);
            Socket sock; //connection between the client and server
            PrintStream toServer; //for printing to the server

            int port = 3000; //port for letting other processes know they should start executing
            try {
                while (port != 3003) { //stop at port 3003 (for all 3 processes)
                    sock = new Socket("localhost", port); //connect to the active server via server name and port
                    toServer = new PrintStream(sock.getOutputStream()); //get the output stream of the server/process
                    toServer.println("START"); //send the signal to the process
                    toServer.flush(); //flush the stream to make sure all bytes are printed out
                    sock.close(); //close the connection with the server
                    port++; //switch ports
                }
            } catch (IOException e) { //catch any input/output exceptions
                e.printStackTrace();
            }


        }
        Thread.sleep(2000); //wait until process 2 triggers other processes
        System.out.println("Reading file... " + file); //print out which file you are reading
        String json = bc.txtFileToJSON(file); //then convert the file into a json string
        BlockchainSender(json); //send the json format to all other processes

        byte[] bytePublicKey = keys.getPublic().getEncoded(); //get the encoded version of the public key for the current process
        String stringKey = Base64.getEncoder().encodeToString(bytePublicKey); //convert it to a String so that it can be sent with JSON
        publicKeySender(stringKey); //multicast the public key to all processes
    }



    private String txtFileToJSON(String file) throws IOException{ //used for creating unverified blocks from files
        BufferedReader br = new BufferedReader(new FileReader(file)); //create a new buffer for reading the file
        String[] fields; //will store the block fields
        String InputLineStr; //will store the data for one block from the file
        String uuid; //will store the uuid

        LinkedList<Block> blocksFromThisFile = new LinkedList<>(); //create a linked list that will store the blocks from the file we are reading from for a given process
        while ((InputLineStr = br.readLine()) != null) { //loop until we reach the end of the file
            Block unverifiedBlock = new Block(); //create a new instance of a block for every line
            try {
                Thread.sleep(1000); //sleep for one second before continuing to make sure that the timestamps are not the same
            } catch (InterruptedException ignored) {
            }
            Date date = new Date(); //create a new instance of a date
            String T1 = String.format("%1$s %2$tF.%2$tT", "", date); //format the date string so that date and time are separated by a period
            String TimeStampString = T1 + "." + processNum; //add pid so that there are no timestamp collisions between the processes
            unverifiedBlock.setTimeStamp(TimeStampString); // set the timestamp of the block

            uuid = UUID.randomUUID().toString(); //generate a random uuid
            unverifiedBlock.setUUID(uuid); //set the uuid for a block
            fields = InputLineStr.split("\\s+"); //split the line of the file by spaces and generate an array
            unverifiedBlock.setFirstName(fields[0]); //set block's first name
            unverifiedBlock.setLastName(fields[1]); //set block's last name
            unverifiedBlock.setDOB(fields[2]); //set block's DOB
            unverifiedBlock.setPhoneNum(fields[3]);//set block's phone number
            unverifiedBlock.setDiagnosis(fields[4]);//set block's diagnosis
            unverifiedBlock.setTreatment(fields[5]);//set block's treatment
            unverifiedBlock.setMed(fields[6]);//set block's medicine

            blocksFromThisFile.add(unverifiedBlock); //add the unverified block that was generated above to the linked list
        }
        Gson gson = new GsonBuilder().setPrettyPrinting().create(); //create new GSON instance
        return gson.toJson(blocksFromThisFile); //convert the Java linked list into json object and return from a function
    }

    public static void BlockchainSender(String json) { //acts as a client that sends the updated blockchain to all other processes when a block is verified
        Socket sock; //connection between the client and server
        PrintStream toServer; //for printing to the server

        int port = 4820; //start sending update blockchain to processes running on ports 4820-4822
        try {
            while (port != 4823) { //stop at port 4822
                sock = new Socket("localhost", port); //connect to the active server via server name and port
                toServer = new PrintStream(sock.getOutputStream()); //get the output stream of the server
                toServer.println(json); //send the json Blockchain to the server
                toServer.flush(); //flush the stream to make sure all bytes are printed out
                sock.close(); //close the connection with the server
                port++; //switch ports
            }
        } catch (IOException e) { //catch any input/output exceptions
            e.printStackTrace();
        }
    }
    public static String generateRandomString() {//Generates random String of length 7/acts as a random seed generator
        byte[] array = new byte[7]; //create a new byte array with 7 positions
        new Random().nextBytes(array); //generate 7 random bytes
        return new String(array, StandardCharsets.UTF_8); //create a string from these bytes
    }

    public static void publicKeySender(String stringKey) { //acts as a client that sends the public key of this process to all other processes
        Gson gson = new GsonBuilder().setPrettyPrinting().create(); //new instance of gson
        // Convert the Java object to a JSON String:
        String json = gson.toJson(stringKey); //convert the string version of the public key of this process to a json string

        Socket sock; //connection between the client and server
        PrintStream toServer; //for printing to the server
        int port = 4710; //public key port by default
        try {
            while (port != 4713) { //loop until we send the public key to all 3 processes
                sock = new Socket("localhost", port); //connect to the active server via server name and port
                toServer = new PrintStream(sock.getOutputStream()); //for printing to the server
                toServer.println(json); //send the json public key to the server
                toServer.println(processNum);
                toServer.flush(); //flush the stream to make sure all bytes are printed out
                sock.close(); //close the connection with the server
                port++; //increase the port number so that other processes receive it as well
            }
        } catch (IOException e) { //catch any input/output exceptions
            e.printStackTrace();
        }
    }

    public static KeyPair generateKeyPair(long seed) throws Exception { //generate the public/private key pair for this process
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA"); //create a new instance of keypair generator
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN"); //get the random number generator
        rng.setSeed(seed); //generate a random number using the provided seed
        keyGenerator.initialize(1024, rng); //generate a key pair using the random number
        return (keyGenerator.generateKeyPair()); //return the key pair
    }
}

class UnverifiedBlockLooper implements Runnable { //server that receives unverified blocks and processes them
    int port; //port on which this server runs

    public UnverifiedBlockLooper(int port) {
        this.port = port;
    } //constructor for initializing the port

    public boolean work(String hash){ //work function that checks if the generated hash solves the puzzle for the block
        for (int i = 0; i < 15; i++) { //for the first 15 chars in the string
            int num = hash.charAt(i); //get the char
            if (num > 53) return false; //if the ascii value of the char is bigger than 53 then the puzzle is not solved and return false
        }
        return true; //return true if the first 15 chars have an ascii value of 53 or less/ puzzle is solved
    }

    public static String generateRandomString() {//Generates random String of length 7/acts as a random seed generator
        byte[] array = new byte[7]; //create a new byte array with 7 positions
        new Random().nextBytes(array); //generate 7 random bytes
        return new String(array, StandardCharsets.UTF_8); //create a string from these bytes
    }

    private String signData(String SHA) throws Exception { //sign the data in the block so that every process can verify who the block verification is coming from
        byte[] digitalSignature = sign(SHA.getBytes(), Blockchain.keys.getPrivate()); //sign hashed data with a private key
        return Base64.getEncoder().encodeToString(digitalSignature); //encode the signed hash to a string format so you can store it in json later
    }

    public static byte[] sign(byte[] data, PrivateKey key) throws Exception { //the signing process
        Signature signer = Signature.getInstance("SHA1withRSA"); //create a new instance of a signer
        signer.initSign(key); //add public key
        signer.update(data); //add data
        return (signer.sign()); //sign the data with public key and return the signed hash
    }

    public void createHash(Blockchain.Block block) throws Exception { //function called by all processes that tries to find a random seed that solves the puzzle
        boolean solved; //is the puzzle solved
        String winningHash; //store the unsigned hash value that gets generated using the winning random seed

        while (true) { //loop forever but exit the loop if you solve the puzzle or until someone else solves the puzzle
            String randomString = generateRandomString(); //generate a random string
            String threeValues = randomString + Blockchain.prevBlockHash
                    + block.getFirstName()
                    + block.getLastName()
                    + block.getTimeStamp()
                    + block.getDiagnosis()
                    + block.getDOB()
                    + block.getMed()
                    + block.getPhoneNum()
                    + block.getTreatment(); //concatenate three values needed to create a hash for the block(random seed, previous block's hash and the data of the current block)

            MessageDigest md = MessageDigest.getInstance("SHA-256"); //get the instance of the MessageDigest that will implement the SHA-256 hash algorithm
            md.update(threeValues.getBytes()); //add our three values to the message digest
            byte[] byteData = md.digest(); //get the hash value of our three values in byte form

            StringBuilder sb = new StringBuilder(); //new instance of a string builder used to store the string version of our hash
            for (byte byteDatum : byteData) { //for all bytes in the previously created array of bytes of our hash
                sb.append(Integer.toString((byteDatum & 0xff) + 0x100, 16).substring(1)); //convert from a byte into string and concatenate
            }
            String SHA256 = sb.toString(); //convert the hash into a String
            solved = work(SHA256); //try to solve the puzzle of the block using the created hash value

            boolean stopWork = false; //used to check if some other process has solved the puzzle
            //checking if someone else solved the puzzle
            for (Blockchain.Block verified : Blockchain.linkedList) { //for all the verified blocks in the current blockchain
                if (verified.getBlockID() == block.getBlockID()) { //if there is a block that has the same blockID as our current block it means that the block has been verified by someone else
                    System.out.printf("Block ID %s SOLVED! (PID: %s) %n", verified.getBlockID(), verified.getVerificationProcessID()); //print a message that some other process solved the puzzle
                    //if some other process solved the work then verify the data
                    //now this process will verify the block
                    byte[] testSignature = Base64.getDecoder().decode(verified.getSignedSHA256()); //get the byte version of the signed hash of the verified block
                    String pKey = Blockchain.publicKeys.get(verified.getVerificationProcessID()); //get the string version of the public key for the block
                    byte[] bytePubkey2 = Base64.getDecoder().decode(pKey); //decode the public key string version into a byte array
                    X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bytePubkey2); //creates new key spec based on the encoded key
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA"); //creates keys
                    PublicKey RestoredKey = keyFactory.generatePublic(pubSpec); //restore the public key so that it is again store in an instance of PublicKey
                    System.out.println(String.format("Block ID %s (Coming from PID: %s) is VERIFIED: ", verified.getBlockID(), verified.getVerificationProcessID()) + verifySig(verified.getWinningHash().getBytes(), RestoredKey, testSignature));
                    stopWork = true; //stop processing in this process because the puzzle is solved
                    break; //break out of this loop
                }
            }

            if (stopWork) { //if someone has solved the puzzle break out of the while loop
                break;
            }

            if (solved) { //if this process has solved the puzzle
                String signedSHA256 = signData(SHA256); //sign the block data
                block.setSignedSHA256(signedSHA256); //set the signed hash for the block
                block.setVerificationProcessID(Blockchain.processNum); //set that this process has solved the puzzle
                block.setRandomSeed(randomString); //seed that solves the puzzle
                winningHash = SHA256; //set the winning hash to be the hash we created last
                Blockchain.prevBlockHash = winningHash; //set the previous block hash of the whole blockchain to be the current hash
                block.setWinningHash(winningHash); //set the winning hash in the block
                Blockchain.linkedList.add(block); //add the block to the blockchain
                sendUpdatedBlockchain(Blockchain.linkedList); //update all other processes that there is a new blockchain
                System.out.printf("Block ID %s SOLVED! (PID: %s)%n", block.getBlockID(), Blockchain.processNum); //change to block id
                break; //get out of the while loop, no need to process anymore
            }
        }
    }

    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception { //make sure that the block is verified by a the owner who signed it
        Signature signer = Signature.getInstance("SHA1withRSA"); //get new signature instance
        signer.initVerify(key); //add the public key to the instance
        signer.update(data); //add the data

        return (signer.verify(sig)); //check if the data was signed with the corresponding private key belonging to the same process as the public key
    }

    private void sendUpdatedBlockchain(LinkedList<Blockchain.Block> linkedList) { //once this process verifies the block, update other processes
        Gson gson = new GsonBuilder().setPrettyPrinting().create(); //new gson instance
        // Convert the Java object to a JSON String:
        String json = gson.toJson(linkedList); //convert the new linked list into a json object
        Socket sock; //connection between the client and server
        PrintStream toServer; //for printing to the server

        int port = 4930; //port for receiving new shared ledgers
        try {
            while (port != 4933) { //loop until all 3 ports receive the ledger
                sock = new Socket("localhost", port); //connect to the active server via server name and port
                toServer = new PrintStream(sock.getOutputStream()); //for printing to the server
                toServer.println(json); //send the json linked list
                toServer.flush(); //flush the stream to make sure all bytes are printed out
                sock.close(); //close the connection with the server
                port++; //increase the port num
            }
        } catch (IOException e) { //catch any input/output exceptions
            e.printStackTrace();
        }
    }

    public void run() { //start processing the thread here
        int q_len = 6; // If the OpSys receives more than 6 requests at the same time, it will only queue the first 6
        Socket sock; //create a socket object to establish a connection between the client and the server

        try {
            int numOfRequests = 0; //number of requests/files we will receive over the network with unverified blocks
            ServerSocket servsock = new ServerSocket(port, q_len); //object that waits for the message over the network
            while (numOfRequests < Blockchain.numOfDataFiles) { //loop until the we receive all the files (3)
                sock = servsock.accept(); // accept the request over the network
                new UnverifiedBlockWorker(sock).start(); //start a new UnverifiedBlockWorker thread to handle the request
                numOfRequests++; //increase the number of request
            }

            Thread.sleep(2000); //wait until all unverified blocks are loaded

            //once all the blocks are in the PQ, try to verify the blocks before other processes
            while (!Blockchain.pq.isEmpty()) { //while there are blocks in the blockchain PQ
                Blockchain.Block block = Blockchain.pq.poll(); //get the block with the oldest timestamp from the queue
                block.setBlockID(Blockchain.N); //set its block id to be N
                createHash(block); //try to solve the puzzle for this block
                Blockchain.N++; //increase blockID
                Thread.sleep(2000); //sleep until all processes are coordinated
            }
            System.out.println("Verified all the blocks. Bye bye!");

        } catch (IOException | InterruptedException | NoSuchAlgorithmException ioe) { //catch any exceptions
            System.out.println(ioe); //print out the exception
        } catch (Exception e) {  //catch any exception
            e.printStackTrace();
        }
    }
}

class UnverifiedBlockWorker extends Thread { // class definition
    Socket sock; // create a socket between this client instance and the server

    UnverifiedBlockWorker(Socket s) {
        sock = s;
    } // constructor that assigns the passed socket to the local variable

    public void run() { //when we start the UnverifiedBlockWorker class, the run method is where we start running the code
        BufferedReader in; //for reading client input
        try {
            in = new BufferedReader //buffer the characters to make the readLine() more efficient
                    (new InputStreamReader //convert the bytes to characters
                            (sock.getInputStream())); //get the input stream from the client
            try {
                String message; //store client's message
                StringBuilder json = new StringBuilder(); //new instance of a string builder
                while ((message = in.readLine()) != null) { //read all the lines
                    json.append(message); //append lined into a string builder
                }
                Gson gson = new Gson(); //new gson instance
                Blockchain.Block[] blocks = gson.fromJson(json.toString(), Blockchain.Block[].class); //convert the received json string into a java object/Block array
                Blockchain.pq.addAll(Arrays.asList(blocks)); //add all the blocks received into a priority queue

            } catch (IOException x) { //catch the input/output exception
                System.out.println("Server read error");
                x.printStackTrace();
            }
            sock.close(); // close this particular client connection, but not the server
        } catch (IOException ioe) {  //catch the input/output exception
            System.out.println(ioe);
        }
    }
}

class PublicKeyLooper implements Runnable { //server that receives all public keys
    int port; //store port

    public PublicKeyLooper(int port) {
        this.port = port;
    } //constructor

    public void run() { //start the thread
        int q_len = 6; // If the OpSys receives more than 6 requests at the same time, it will only queue the first 6
        Socket sock; //create a socket object to establish a connection between the client and the server

        try {
            ServerSocket servsock = new ServerSocket(port, q_len); //object that waits for the public keys over the network
            int req = 0; //number of public keys we will receive (one process=one public key)
            while (req!=3) { //loop until we receive 3 public keys
                sock = servsock.accept(); // accept the request over the network
                req++; //increase the request number
                new PublicKeyWorker(sock).start(); //start a new PublicKeyWorker thread to handle the request
            }
            System.out.println("Received all public keys.\n");

        } catch (IOException ioe) { //catch any exceptions coming from input/output streams
            System.out.println(ioe); //print out the exception
        }
    }
}

class PublicKeyWorker extends Thread { //server for receiving all public keys
    Socket sock; // create a socket between this client instance and the server

    PublicKeyWorker(Socket s) {
        sock = s;
    } // constructor that assigns the passed socket to the local variable

    public void run() { //where the thread starts running
        BufferedReader in; //for reading client input
        try {
            in = new BufferedReader //buffer the characters to make the readLine() more efficient
                    (new InputStreamReader //convert the bytes to characters
                            (sock.getInputStream())); //get the input stream from the client
            try {
                Gson gson = new Gson(); //new instance of a json
                String message; //variable to store the input from the key sender
                message = in.readLine(); //public key
                String publicKey = gson.fromJson(message, String.class); //convert the public key to a String from a json object

                int processID; //store the public key in a hash table along with its process id
                processID = Integer.parseInt(in.readLine()); //parse the pid string to an Integer
                Blockchain.publicKeys.put(processID, publicKey); //store pid:publicKey pair into a HashMap so that we can later verify the block with a corresponding public key

            } catch (IOException x) { //catch any input/output exception
                System.out.println("Server read error");
                x.printStackTrace();
            }
            sock.close(); // close this particular client connection, but not the server
        } catch (IOException ioe) { //catch any input/output exception
            System.out.println(ioe);
        }
    }
}


class BlockchainLooper implements Runnable {//server used for receiving updated Blockchain
    int port; //store the port we are using for the connection

    public BlockchainLooper(int port) {
        this.port = port;
    } //constructor and initialize the port

    public void run() { //Starting blockchain looper thread
        int q_len = 6; // If the OpSys receives more than 6 requests at the same time, it will only queue the first 6
        Socket sock; //create a socket object to establish a connection between the client and the server

        try {
            ServerSocket servsock = new ServerSocket(port, q_len); //object that waits for the updates from other processes about shared ledger
            int records = 0; //for each record/block there can be one update when the block is verified, store the number of updates here
            while (records != 12) { //for 12 records in 3 files, there will be a total of 12 requests over the network
                sock = servsock.accept(); // accept the update
                records++; //increase the record number
                new BlockchainWorker(sock).start(); //start a new BlockchainWorker thread to handle the request
            }
        } catch (IOException ioe) { //catch any exceptions coming from input/output streams
            System.out.println(ioe); //print out the exception
        }
    }
}

class BlockchainWorker extends Thread { // class definition
    Socket sock; // create a socket between this client instance and the server

    BlockchainWorker(Socket s) {
        sock = s;
    } // constructor that assigns the passed socket to the local variable

    public void run() { //start the thread
        BufferedReader in; //for reading client input
        try {
            in = new BufferedReader //buffer the characters to make the readLine() more efficient
                    (new InputStreamReader //convert the bytes to characters
                            (sock.getInputStream())); //get the input stream from the client
            try {
                String message; //store the clients message here
                StringBuilder json = new StringBuilder(); //new instance of a string builder
                while ((message = in.readLine()) != null) {//read the lines of the json
                    json.append(message); //append each line into a string builder
                }
                Gson gson = new Gson(); //new gson instance
                LinkedList<Blockchain.Block> ll = new LinkedList<>(); //new linked list instance for storing all the blocks from the updated linked list
                Blockchain.Block[] blocks = gson.fromJson(json.toString(), Blockchain.Block[].class); //convert the json blocks into java array with Blocks
                Collections.addAll(ll, blocks); //add all the blocks into the linked list
                Blockchain.linkedList = ll; //update the blockchain linked list

                if (Blockchain.processNum == 2) {
                    Container c = new Container();
                    c.setLayout(new BoxLayout(c,BoxLayout.Y_AXIS));
                    JTextArea label = new JTextArea(8,1);
                    JButton button = new JButton("Block " + Blockchain.counter);
                    button.setAlignmentX(Component.CENTER_ALIGNMENT);
                    button.addActionListener(new ActionListener(){
                        boolean clicked = false;
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            //display the info for a block
                            if(clicked==false) {
                                label.setVisible(true);
                                clicked = true;
                            }else{
                                label.setVisible(false);
                                clicked = false;
                            }
                        }
                    });
                    Blockchain.Block current = Blockchain.linkedList.getLast();
                    label.append("First Name: " + current.firstName+ "\n");
                    label.append("Last Name: " +current.lastName+ "\n");
                    label.append("DOB: "+current.DOB + "\n");
                    label.append("Phone number: " +current.phoneNum+ "\n");
                    label.append("Diagnosis: "+current.diagnosis+ "\n");
                    label.append("Treatment: "+current.treatment+ "\n");
                    label.append("Medicine: "+current.med + "\n");
                    label.append("Verified by: PID "+ current.verificationProcessID);

                    label.setVisible(false);
                    c.add(button);
                    c.add(label);

                    Blockchain.panel.add(c); // Adds Button to content pane of frame
                    //Blockchain.panel.add(label);
                    Blockchain.counter++;
                    Blockchain.frame.setVisible(true);

                }

                if (Blockchain.processNum == 0) { //if we are in process 0 then write the ledger to a file
                    try (FileWriter writer = new FileWriter("BlockchainLedger.json")) { //write the current ledger to a file using FileWriter
                        gson.toJson(Blockchain.linkedList, writer); //convert to json and then write to a file
                    } catch (IOException e) { //catch any i/o exceptions
                        e.printStackTrace();
                    }
                }
            } catch (IOException x) { //catch the input/output exception
                System.out.println("Server read error");
                x.printStackTrace();
            }
            sock.close(); // close this particular client connection, but not the server
        } catch (IOException ioe) { //catch the input/output exception
            System.out.println(ioe);
        }
    }
}

class Starter implements Runnable {//server used for receiving signal from process 2
    int port; //store the port we are using for the connection

    public Starter(int port) {
        this.port = port;
    } //constructor and initialize the port

    public void run() { //Starting the thread

        int q_len = 6; // If the OpSys receives more than 6 requests at the same time, it will only queue the first 6
        Socket socket = null; //create a socket object to establish a connection between the client and the server

        ServerSocket servsock = null; //object that waits for the signal over the network
        try {
            servsock = new ServerSocket(3000+Blockchain.processNum, q_len); //initialize the socket to talk to the client
        } catch (IOException e) { //catch any input/output exceptions
            e.printStackTrace();
        }
        try {
            socket = servsock.accept(); // accept the request over the network
        } catch (IOException e) {
            e.printStackTrace();
        }
        BufferedReader in; //for reading client input
            try {
                in = new BufferedReader //buffer the characters to make the readLine() more efficient
                        (new InputStreamReader //convert the bytes to characters
                                (socket.getInputStream())); //get the input stream from the client
                String message; //store client's message
                message = in.readLine();
                if (message.equals("START")) {
                    System.out.println("Process 2 is on, starting...");
                }
                socket.close(); // close this particular client connection, but not the server
            } catch (IOException ioe) {  //catch the input/output exception
                System.out.println(ioe);
            }
        }
    }


