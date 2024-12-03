//
//  ServerInfo.swift
//
//
//  Created by Denis Angell on 7/30/22.
//

// https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/models/methods/serverInfo.ts

import Foundation

/**
 The `server_info` command asks the server for a human-readable version of
 various information about the rippled server being queried. Expects a
 response in the form of a {@link ServerInfoResponse}.
 */
public class ServerInfoRequest: BaseRequest {
    public init(
        // Base Request
        id: Int? = nil,
        apiVersion: Int? = nil
    ) {
        super.init(id: id, command: "server_info", apiVersion: apiVersion)
    }

    override public init(_ json: [String: AnyObject]) throws {
        try super.init(json)
    }

    required init(from decoder: Decoder) throws {
        try super.init(from: decoder)
    }

    override public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try super.encode(to: encoder)
    }
}

public typealias ServerState = String
// export type ServerState =
//  | 'disconnected'
//  | 'connected'
//  | 'syncing'
//  | 'tracking'
//  | 'full'
//  | 'validating'
//  | 'proposing'

public class StateAccounting: Codable {
    public var durationUs: String
    public var transitions: String

    enum CodingKeys: String, CodingKey {
        case durationUs = "duration_us"
        case transitions = "transitions"
    }
}

public class JobType: Codable {
    let jobType: String
    let perSecond: Int
    let peakTime: Int?
    let avgTime: Int?
    let inProgress: Int?

    enum CodingKeys: String, CodingKey {
        case jobType = "job_type"
        case perSecond = "per_second"
        case peakTime = "peak_time"
        case avgTime = "avg_time"
        case inProgress = "in_progress"
    }
}

public class InfoLedger: Codable {
    /// The time since the ledger was closed, in seconds.
    public var age: Int
    /**
     Base fee, in XRP. This may be represented in scientific notation.
     Such as 1e-05 for 0.00005.
     */
    public var baseFeeXrp: Double
    /// Unique hash for the ledger, as hexadecimal.
    public var hash: String
    /**
     Minimum amount of XRP (not drops) necessary for every account to.
     Keep in reserve .
     */
    public var reserveBaseXrp: Int
    /**
     Amount of XRP (not drops) added to the account reserve for each
     object an account owns in the ledger.
     */
    public var reserveIncXrp: Double
    /// The ledger index of the latest validated ledger.
    public var seq: Int

    enum CodingKeys: String, CodingKey {
        case age = "age"
        case baseFeeXrp = "base_fee_xrp"
        case hash = "hash"
        case reserveBaseXrp = "reserve_base_xrp"
        case reserveIncXrp = "reserve_inc_xrp"
        case seq = "seq"
    }
}

public class StateLoad: Codable {
    /**
     (Admin only) Information about the rate of different types of jobs
     the server is doing and how much time it spends on each.
     */
    public var jobTypes: [JobType]
    /// (Admin only) The number of threads in the server's main job pool.
    public var threads: Int

    enum CodingKeys: String, CodingKey {
        case jobTypes = "job_types"
        case threads = "threads"
    }
}

public class LastClosed: Codable {
    /**
     The amount of time it took to reach a consensus on the most recently
     validated ledger version, in seconds.
     */
    public var convergeTimeS: Double
    /**
     How many trusted validators the server considered (including itself,
     if configured as a validator) in the consensus process for the most
     recently validated ledger version.
     */
    public var proposers: Int

    enum CodingKeys: String, CodingKey {
        case convergeTimeS = "converge_time_s"
        case proposers = "proposers"
    }
}

public class ServerInfoWrapper: Codable {
    /**
     If true, this server is amendment blocked. If the server is not
     amendment blocked, the response omits this field.
     */
    public var amendmentBlocked: Bool?
    /// The version number of the running rippled version.
    public var buildVersion: String?
    /**
     Information on the most recently closed ledger that has not been
     validated by consensus. If the most recently validated ledger is
     available, the response omits this field and includes
     `validated_ledger` instead. The member fields are the same as the.
     `validated_ledger` field.
     */
    public var closedLedger: InfoLedger?
    /**
     Range expression indicating the sequence numbers of the ledger
     versions the local rippled has in its database.
     */
    public var completeLedgers: String
    /**
     On an admin request, returns the hostname of the server running the
     rippled instance; otherwise, returns a single RFC-1751  word based on
     the node public key.
     */
    public var hostid: String?
    /**
     Amount of time spent waiting for I/O operations, in milliseconds. If
     this number is not very, very low, then the rippled server is probably
     having serious load issues.
     */
    public var ioLatencyMs: Int?
    /**
     The number of times (since starting up) that this server has had over
     250 transactions waiting to be processed at once. A large number here
     may mean that your server is unable to handle the transaction load of
     the XRP Ledger network.
     */
    public var jqTransOverflow: String?
    /**
     Information about the last time the server closed a ledger, including
     the amount of time it took to reach a consensus and the number of
     trusted validators participating.
     */
    public var lastClose: LastClosed?
    /**
     (Admin only) Detailed information about the current load state of the
     server.
     */
    public var load: StateLoad?
    /**
     The load-scaled open ledger transaction cost the server is currently
     enforcing, as a multiplier on the base transaction cost. For example,
     at 1000 load factor and a reference transaction cost of 10 drops of
     XRP, the load-scaled transaction cost is 10,000 drops (0.01 XRP). The
     load factor is determined by the highest of the individual server's
     load factor, the cluster's load factor, the open ledger cost and the
     overall network's load factor.
     */
    public var loadFactor: Int?
    /**
     Current multiplier to the transaction cost based on
     load to this server.
     */
    public var loadFactorLocal: Int?
    /**
     Current multiplier to the transaction cost being used by the rest of
     the network.
     */
    public var loadFactorNet: Int?
    /**
     Current multiplier to the transaction cost based on load to servers
     in this cluster.
     */
    public var loadFactorCluster: Int?
    /**
     The current multiplier to the transaction cost that a transaction must
     pay to get into the open ledger.
     */
    public var loadFactorFeeEscalation: Int?
    /**
     The current multiplier to the transaction cost that a transaction must
     pay to get into the queue, if the queue is full.
     */
    public var loadFactorFeeQueue: Int?
    /**
     The load factor the server is enforcing, not including the open ledger
     cost.
     */
    public var loadFactorServer: Int?
    public var networkLedger: String? = "waiting"
    /// How many other rippled servers this one is currently connected to.
    public var peers: Int?
    /**
     Public key used to verify this server for peer-to-peer communications.
     This node key pair is automatically generated by the server the first
     time it starts up. (If deleted, the server can create a new pair of
     Keys.).
     */
    public var pubkeyNode: String?
    /// Public key used by this node to sign ledger validations.
    public var pubkeyValidator: String?
    /**
     A string indicating to what extent the server is participating in the
     network.
     */
    public var serverState: ServerState?
    /**
     The number of consecutive microseconds the server has been in the
     current state.
     */
    public var serverStateDurationUs: String?
    /**
     A map of various server states with information about the time the
     server spends in each. This can be useful for tracking the long-term
     health of your server's connectivity to the network.
     */
    public var stateAccounting: [ServerState: StateAccounting]?
    /// The current time in UTC, according to the server's clock.
    public var time: String?
    /// Number of consecutive seconds that the server has been operational.
    public var uptime: Int?
    /// Information about the most recent fully-validated ledger.
    public var validatedLedger: InfoLedger?
    /**
     Minimum number of trusted validations required to validate a ledger
     version. Some circumstances may cause the server to require more
     validations.
     */
    public var validationQuorum: Int
    /**
     Either the human readable time, in UTC, when the current validator
     list will expire, the string unknown if the server has yet to load a
     published validator list or the string never if the server uses a
     static validator list.
     */
    public var validatorListExpires: String?

    enum CodingKeys: String, CodingKey {
        case amendmentBlocked = "amendment_blocked"
        case buildVersion = "build_version"
        case closedLedger = "closed_ledger"
        case completeLedgers = "complete_ledgers"
        case hostid = "hostid"
        case ioLatencyMs = "io_latency_ms"
        case jqTransOverflow = "jq_trans_overflow"
        case lastClose = "last_close"
        case load = "load"
        case loadFactor = "load_factor"
        case loadFactorLocal = "load_factor_local"
        case loadFactorNet = "load_factor_net"
        case loadFactorCluster = "load_factor_cluster"
        case loadFactorFeeEscalation = "load_factor_fee_escalation"
        case loadFactorFeeQueue = "load_factor_fee_queue"
        case loadFactorServer = "load_factor_server"
        case networkLedger = "network_ledger"
        case peers = "peers"
        case pubkeyNode = "pubkey_node"
        case pubkeyValidator = "pubkey_validator"
        case serverState = "server_state"
        case serverStateDurationUs = "server_state_duration_us"
        case stateAccounting = "state_accounting"
        case time = "time"
        case uptime = "uptime"
        case validatedLedger = "validated_ledger"
        case validationQuorum = "validation_quorum"
        case validatorListExpires = "validator_list_expires"
    }

    public required init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        amendmentBlocked = try values.decodeIfPresent(Bool.self, forKey: .amendmentBlocked)
        buildVersion = try values.decodeIfPresent(String.self, forKey: .buildVersion)
        closedLedger = try values.decodeIfPresent(InfoLedger.self, forKey: .closedLedger)
        completeLedgers = try values.decode(String.self, forKey: .completeLedgers)
        hostid = try values.decodeIfPresent(String.self, forKey: .hostid)
        ioLatencyMs = try values.decodeIfPresent(Int.self, forKey: .ioLatencyMs)
        jqTransOverflow = try values.decodeIfPresent(String.self, forKey: .jqTransOverflow)
        lastClose = try values.decodeIfPresent(LastClosed.self, forKey: .lastClose)
        load = try values.decodeIfPresent(StateLoad.self, forKey: .load)
        loadFactor = try values.decodeIfPresent(Int.self, forKey: .loadFactor)
        loadFactorLocal = try values.decodeIfPresent(Int.self, forKey: .loadFactorLocal)
        loadFactorNet = try values.decodeIfPresent(Int.self, forKey: .loadFactorNet)
        loadFactorCluster = try values.decodeIfPresent(Int.self, forKey: .loadFactorCluster)
        loadFactorFeeEscalation = try values.decodeIfPresent(Int.self, forKey: .loadFactorFeeEscalation)
        loadFactorFeeQueue = try values.decodeIfPresent(Int.self, forKey: .loadFactorFeeQueue)
        loadFactorServer = try values.decodeIfPresent(Int.self, forKey: .loadFactorServer)
        networkLedger = try values.decodeIfPresent(String.self, forKey: .networkLedger)
        peers = try values.decodeIfPresent(Int.self, forKey: .peers)
        pubkeyNode = try values.decodeIfPresent(String.self, forKey: .pubkeyNode)
        pubkeyValidator = try values.decodeIfPresent(String.self, forKey: .pubkeyValidator)
        serverState = try values.decodeIfPresent(String.self, forKey: .serverState)
        serverStateDurationUs = try values.decodeIfPresent(String.self, forKey: .serverStateDurationUs)
        stateAccounting = try values.decodeIfPresent([ServerState: StateAccounting].self, forKey: .stateAccounting)
        time = try values.decodeIfPresent(String.self, forKey: .time)
        uptime = try values.decodeIfPresent(Int.self, forKey: .uptime)
        validatedLedger = try values.decodeIfPresent(InfoLedger.self, forKey: .validatedLedger)
        validationQuorum = try values.decode(Int.self, forKey: .validationQuorum)
        validatorListExpires = try values.decodeIfPresent(String.self, forKey: .validatorListExpires)
    }

    func toJson() throws -> [String: AnyObject] {
        let data = try JSONEncoder().encode(self)
        let jsonResult = try JSONSerialization.jsonObject(with: data, options: .mutableLeaves)
        return jsonResult as? [String: AnyObject] ?? [:]
    }
}

/**
 Response expected from a {@link ServerInfoRequest}.
 *
 @category Responses
 */
public class ServerInfoResponse: Codable {
    public var info: ServerInfoWrapper
}
