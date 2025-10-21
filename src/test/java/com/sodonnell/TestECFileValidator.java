package com.sodonnell;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.apache.hadoop.hdfs.protocol.ErasureCodingPolicy;
import org.apache.hadoop.hdfs.protocol.LocatedBlock;
import org.apache.hadoop.hdfs.protocol.LocatedBlocks;
import org.apache.hadoop.hdfs.protocol.LocatedStripedBlock;
import org.apache.hadoop.hdfs.protocol.SystemErasureCodingPolicies;
import org.apache.hadoop.hdfs.server.datanode.DataNode;
import org.apache.hadoop.hdfs.util.StripedBlockUtil;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import static junit.framework.TestCase.assertEquals;

public class TestECFileValidator {

  private Logger LOG = LoggerFactory.getLogger(TestECFileValidator.class);

  private static Configuration conf;
  private static MiniDFSCluster cluster;
  private static DFSClient client;
  private static String policyName = "RS-6-3-1024k";
  private static ErasureCodingPolicy ecPolicy = SystemErasureCodingPolicies.getByName(policyName);
  private static DistributedFileSystem fs;
  private Path ecRoot = new Path("/ecfiles");

  @BeforeClass
  public static void createCluster() throws IOException {
    conf = new Configuration();
    // Set block size to 2MB
    conf.setInt(DFSConfigKeys.DFS_BLOCK_SIZE_KEY, 1024*1024*2);
    // Avoid EC files failing to completely write due to load on the mini-cluster
    conf.setBoolean("dfs.namenode.redundancy.considerLoad", false);
    int numDataNodes = ecPolicy.getNumDataUnits() + ecPolicy.getNumParityUnits();
    cluster = new MiniDFSCluster.Builder(conf).numDataNodes(numDataNodes).build();
    cluster.waitActive();
    fs = cluster.getFileSystem();
    fs.enableErasureCodingPolicy(policyName);
    client = new DFSClient(fs.getUri(), conf);
  }

  @Before
  public void setup() throws IOException {
    fs.mkdirs(ecRoot);
    fs.setErasureCodingPolicy(ecRoot, policyName);
  }

  @After
  public void teardown() throws IOException {
    fs.delete(ecRoot, true);
  }

  @AfterClass
  public static void stopCluster() {
    if (cluster != null) {
      cluster.shutdown();
    }
  }

  @Test
  public void testFileWithSingleBlockIsValid() throws Exception {
    Path ecFile = new Path(ecRoot, "ecFile");

    // write one full stripe
    int bytes = ecPolicy.getNumDataUnits() * ecPolicy.getCellSize();
    createFileOfLength(ecFile, bytes);

    ECFileValidator validator = new ECFileValidator(conf);
    ValidationReport report = validator.validate("/ecfiles/ecFile", true);
    assertEquals(true, report.isHealthy());
    assertEquals(1, report.validBlockGroups().size());
    assertEquals(1, report.validBlockGroups().get(0).stripesChecked());
    assertEquals(0, report.corruptBlockGroups().size());
  }

  @Test
  public void testFileWithMultipleBlocksIsValid() throws Exception {
    Path ecFile = new Path(ecRoot, "ecFile");

    // write 3 full stripes - that will be two blocks (block size of 2MB)
    int bytes = ecPolicy.getNumDataUnits() * ecPolicy.getCellSize() * 3;
    createFileOfLength(ecFile, bytes);

    ECFileValidator validator = new ECFileValidator(conf);
    ValidationReport report = validator.validate("/ecfiles/ecFile", true);
    assertEquals(true, report.isHealthy());
    assertEquals(2, report.validBlockGroups().size());
    assertEquals(1, report.validBlockGroups().get(0).stripesChecked());
    assertEquals(1, report.validBlockGroups().get(1).stripesChecked());

    // validate again, this time checking all stripes.
    report = validator.validate("/ecfiles/ecFile", false);
    assertEquals(true, report.isHealthy());
    assertEquals(2, report.validBlockGroups().size());
    assertEquals(2, report.validBlockGroups().get(0).stripesChecked());
    assertEquals(1, report.validBlockGroups().get(1).stripesChecked());
  }

  @Test
  public void testFileWithCorruptParityIsInValid() throws Exception {
    //  Not enough replicas was chosen. Reason: {NODE_TOO_BUSY=2}
    Path ecFile = new Path(ecRoot, "ecFile");

    // write 3 full stripes - that will be two blocks (block size of 2MB)
    int bytes = ecPolicy.getNumDataUnits() * ecPolicy.getCellSize() * 3;
    createFileOfLength(ecFile, bytes);

    ECFileValidator validator = new ECFileValidator(conf);
    assertEquals(true, validator.validate("/ecfiles/ecFile", true).isHealthy());

    // When corrupting the parity, you need to ensure the correct checksums go into the
    // meta file. Therefore the easiest way to corrupt it, is to copy another block of
    // the same size in its place - ie the first datablock. So we find the location of
    // the first parity, and the first datablock and then copy the datablock over the
    // parity.
    LocatedBlocks blocks = client.getNamenode().getBlockLocations("/ecfiles/ecFile", 0, bytes);
    LocatedStripedBlock blockGroup = (LocatedStripedBlock) blocks.getLocatedBlocks().get(0);
    final LocatedBlock[] blks = StripedBlockUtil.parseStripedBlockGroup(
        blockGroup, ecPolicy.getCellSize(), ecPolicy.getNumDataUnits(), ecPolicy.getNumParityUnits());

    LocatedBlock parityLb = blks[ecPolicy.getNumDataUnits()+1];
    int DNPort = parityLb.getLocations()[0].getIpcPort();
    int DNIndex = findDNIndex(DNPort);

    File parityFile = cluster.getBlockFile(DNIndex, parityLb.getBlock());
    File parityMetaFile = cluster.getBlockMetadataFile(DNIndex, parityLb.getBlock());

    LocatedBlock dataLb = blks[0];
    DNPort = dataLb.getLocations()[0].getIpcPort();
    DNIndex = findDNIndex(DNPort);

    File dataFile = cluster.getBlockFile(DNIndex, dataLb.getBlock());
    File dataMetaFile = cluster.getBlockMetadataFile(DNIndex, dataLb.getBlock());

    FileUtils.copyFile(dataFile, parityFile);
    FileUtils.copyFile(dataMetaFile, parityMetaFile);

    ValidationReport report = validator.validate("/ecfiles/ecFile", true);
    assertEquals(false, report.isHealthy());
    // first block is corrupt
    assertEquals(blocks.get(0).getBlock().getLocalBlock().toString(), report.corruptBlockGroups().get(0).block());
    // Second block is valid
    assertEquals(blocks.get(1).getBlock().getLocalBlock().toString(), report.validBlockGroups().get(0).block());
  }

  @Test
  public void testCorruptionNotInFirstStripeDetected() throws Exception {
    //  Not enough replicas was chosen. Reason: {NODE_TOO_BUSY=2}
    Path ecFile = new Path(ecRoot, "ecFile");

    // write 3 full stripes - that will be two blocks (block size of 2MB)
    int bytes = ecPolicy.getNumDataUnits() * ecPolicy.getCellSize() * 3;
    createFileOfLength(ecFile, bytes);

    LocatedBlocks blocks = client.getNamenode().getBlockLocations("/ecfiles/ecFile", 0, bytes);
    LocatedStripedBlock blockGroup = (LocatedStripedBlock) blocks.getLocatedBlocks().get(0);
    final LocatedBlock[] blks = StripedBlockUtil.parseStripedBlockGroup(
        blockGroup, ecPolicy.getCellSize(), ecPolicy.getNumDataUnits(), ecPolicy.getNumParityUnits());

    LocatedBlock parityLb = blks[ecPolicy.getNumDataUnits()+1];
    int DNPort = parityLb.getLocations()[0].getIpcPort();
    int DNIndex = findDNIndex(DNPort);

    File parityFile = cluster.getBlockFile(DNIndex, parityLb.getBlock());

    RandomAccessFile f = new RandomAccessFile(parityFile, "rw");
    f.seek(f.length() - 1);
    byte val = f.readByte();
    val++;
    f.seek(f.length() - 1);
    f.write(val);
    f.close();

    try {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS, false);
      ECFileValidator validator = new ECFileValidator(conf);

      ValidationReport report = validator.validate("/ecfiles/ecFile", true);
      assertEquals(true, report.isHealthy());

      report = validator.validate("/ecfiles/ecFile", false);
      assertEquals(false, report.isHealthy());

      // first block is corrupt
      assertEquals(blocks.get(0).getBlock().getLocalBlock().toString(), report.corruptBlockGroups().get(0).block());
      // At the second stripe
      assertEquals(2, report.corruptBlockGroups().get(0).stripesChecked());
      // Second block is valid
      assertEquals(blocks.get(1).getBlock().getLocalBlock().toString(), report.validBlockGroups().get(0).block());
    } finally {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS,
          ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS_DEFAULT);
    }
  }

  @Test
  public void testCorruptionWithZeroParity() throws Exception {
    //  Not enough replicas was chosen. Reason: {NODE_TOO_BUSY=2}
    Path ecFile = new Path(ecRoot, "ecFile");

    // write 3 full stripes - that will be two blocks (block size of 2MB)
    int bytes = ecPolicy.getNumDataUnits() * ecPolicy.getCellSize() * 3;
    createFileOfLength(ecFile, bytes);

    LocatedBlocks blocks = client.getNamenode().getBlockLocations("/ecfiles/ecFile", 0, bytes);
    LocatedStripedBlock blockGroup = (LocatedStripedBlock) blocks.getLocatedBlocks().get(0);
    final LocatedBlock[] blks = StripedBlockUtil.parseStripedBlockGroup(
        blockGroup, ecPolicy.getCellSize(), ecPolicy.getNumDataUnits(), ecPolicy.getNumParityUnits());

    LocatedBlock parityLb = blks[ecPolicy.getNumDataUnits()+1];
    int DNPort = parityLb.getLocations()[0].getIpcPort();
    int DNIndex = findDNIndex(DNPort);

    File parityFile = cluster.getBlockFile(DNIndex, parityLb.getBlock());

    // Zero the first stripe of the parity
    RandomAccessFile f = new RandomAccessFile(parityFile, "rw");
    f.seek(0);
    for (int i=0; i< ecPolicy.getCellSize(); i++) {
      f.write((byte)0);
    }
    f.close();

    try {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS, false);
      ECFileValidator validator = new ECFileValidator(conf);

      // As the first stripe is corrupt, even though parity is non-zero in later stripes
      // that will never get checked.
      ValidationReport report = validator.validate("/ecfiles/ecFile", false);
      assertEquals(false, report.isHealthy());
      assertEquals(true, report.isParityAllZero());

    } finally {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS,
          ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS_DEFAULT);
    }
  }

  @Test
  public void testCorruptionWithFileOfZeros() throws Exception {
    //  Not enough replicas was chosen. Reason: {NODE_TOO_BUSY=2}
    Path ecFile = new Path(ecRoot, "ecFile");

    // write 3 full stripes - that will be two blocks (block size of 2MB)
    int bytes = ecPolicy.getNumDataUnits() * ecPolicy.getCellSize() * 3;
    createFileOfZeros(ecFile, bytes);

    LocatedBlocks blocks = client.getNamenode().getBlockLocations("/ecfiles/ecFile", 0, bytes);
    LocatedStripedBlock blockGroup = (LocatedStripedBlock) blocks.getLocatedBlocks().get(0);
    final LocatedBlock[] blks = StripedBlockUtil.parseStripedBlockGroup(
        blockGroup, ecPolicy.getCellSize(), ecPolicy.getNumDataUnits(), ecPolicy.getNumParityUnits());

    LocatedBlock parityLb = blks[ecPolicy.getNumDataUnits()+1];
    int DNPort = parityLb.getLocations()[0].getIpcPort();
    int DNIndex = findDNIndex(DNPort);

    File parityFile = cluster.getBlockFile(DNIndex, parityLb.getBlock());

    // Zero add some non-zero in the second stripe of the parity
    RandomAccessFile f = new RandomAccessFile(parityFile, "rw");
    f.seek(ecPolicy.getCellSize());
    f.write((byte)1);
    f.close();

    try {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS, false);
      ECFileValidator validator = new ECFileValidator(conf);

      // First stripe should be valid, but parity is reported as zeros
      ValidationReport report = validator.validate("/ecfiles/ecFile", true);
      assertEquals(true, report.isHealthy());
      assertEquals(true, report.isParityAllZero());

      // Second stripe is corrupt, parity still all zeros as the other parity blocks
      // will have zeros in them.
      report = validator.validate("/ecfiles/ecFile", false);
      assertEquals(false, report.isHealthy());
      assertEquals(true, report.isParityAllZero());
    } finally {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS,
          ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS_DEFAULT);
    }
  }
  
  @Test
  public void testCorruptionWithDataFileOfZeros() throws Exception {
    //  Not enough replicas was chosen. Reason: {NODE_TOO_BUSY=2}
    Path ecFile = new Path(ecRoot, "ecFile");
    
    // write 3 full stripes - that will be two blocks (block size of 2MB)
    int bytes = ecPolicy.getNumDataUnits() * ecPolicy.getCellSize() * 3;
    createFileOfLength(ecFile, bytes);
    
    LocatedBlocks blocks = client.getNamenode().getBlockLocations("/ecfiles/ecFile", 0, bytes);
    LocatedStripedBlock blockGroup = (LocatedStripedBlock) blocks.getLocatedBlocks().get(0);
    final LocatedBlock[] blks = StripedBlockUtil.parseStripedBlockGroup(
            blockGroup, ecPolicy.getCellSize(), ecPolicy.getNumDataUnits(), ecPolicy.getNumParityUnits());
    
    LocatedBlock dataLb = blks[ecPolicy.getNumDataUnits()-1];
    int DNPort = dataLb.getLocations()[0].getIpcPort();
    int DNIndex = findDNIndex(DNPort);
    
    File dataFile = cluster.getBlockFile(DNIndex, dataLb.getBlock());
    
    // Zero add some non-zero in the second stripe of the parity
    RandomAccessFile f = new RandomAccessFile(dataFile, "rw");
    f.seek(ecPolicy.getCellSize());
    f.write((byte)1);
    f.close();
    
    try {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS, false);
      ECFileValidator validator = new ECFileValidator(conf);
      
      // First stripe should be valid, but parity is reported as zeros
      ValidationReport report = validator.validate("/ecfiles/ecFile", true);
      assertEquals(true, report.isHealthy());
      
      // Second stripe is corrupt, parity still all zeros as the other parity blocks
      // will have zeros in them.
      report = validator.validate("/ecfiles/ecFile", false);
      assertEquals(false, report.isHealthy());
      assertEquals(true, report.isCorrupt());
    } finally {
      conf.setBoolean(ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS,
              ECValidatorConfigKeys.ECVALIDATOR_VERIFY_CHECKSUMS_DEFAULT);
    }
  }


  private int findDNIndex(int ipcPort) throws Exception {
    int i = 0;
    for (DataNode dn : cluster.getDataNodes()) {
      if (dn.getIpcPort() == ipcPort) {
        return i;
      }
      i++;
    }
    throw new Exception("No datanode found with port "+ipcPort);
  }

  private void createFileOfLength(Path dest, int bytes) throws IOException {
    FSDataOutputStream stream = null;
    try {
      stream = fs.create(dest);
      for (int i = 0; i < bytes; i++) {
        stream.write(RandomUtils.nextBytes(1));
      }
    } finally {
      stream.close();
    }
  }

  private void createFileOfZeros(Path dest, int bytes) throws IOException {
    FSDataOutputStream stream = null;
    try {
      stream = fs.create(dest);
      for (int i = 0; i < bytes; i++) {
        stream.write((byte)0);
      }
    } finally {
      stream.close();
    }
  }

}
