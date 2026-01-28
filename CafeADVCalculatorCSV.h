#pragma once

/******************************************************************************
 * CafeADVCalculator with CSV Support
 * 
 * This extends the original CafeADVCalculator to support loading ADV data
 * from a pre-generated CSV file at startup, avoiding per-instrument DB queries.
 * 
 * CSV is a fast-path optimization. Cache miss falls back to DB query.
 * Workers created from CSV still have full functionality (onBing, onUpdate, etc.)
 * 
 * Usage:
 *   // CSV mode with DB fallback
 *   auto calc = CafeADVCalculator(csvPath, mds, staticDataSource, timeManager, asyncDbPool, flog);
 *   
 *   // Original DB mode only
 *   auto calc = CafeADVCalculator(mds, staticDataSource, timeManager, asyncDbPool, flog);
 * 
 * CSV Format:
 *   ric,scope,date,daily_volume,opening_volume,closing_volume,avg_trade_size,avg_continuous_trade_size,special_day_multiplier
 *   AAPL.O,PRIMARY,2025-01-24,1000000.0,50000.0,75000.0,150.5,145.2,1.0
 * 
 * IMPORTANT: Requires modified CafeADVWorker with additional constructor.
 *            See CafeADVWorker_changes.cpp for required modifications.
 * 
 *****************************************************************************/

#include "ADVDynamicModelCache.h"
#include "ADVDescription.h"
#include "ADVData.h"
#include "ADVSpecification.h"
#include "ADVError.h"
#include "MessageDeliveryService.h"
#include "InstrumentStaticSource.h"
#include "TimeManager.h"
#include "AsyncDbPool.h"
#include "FLog.h"
#include "CSVParser.h"

#include <string>
#include <unordered_map>
#include <memory>
#include <optional>

namespace volt::analysis {

/******************************************************************************
 * CafeADVCalculator
 * 
 * Factory class that creates ADV workers.
 * Supports two modes:
 *   1. CSV mode: Pre-loads data from CSV, O(1) lookup, DB fallback on miss
 *   2. DB mode:  Original behavior, one DB query per create()
 * 
 * In both modes, created workers are full CafeADVWorker instances with
 * all update capabilities (onBing, onUpdate, onTransactionCompleted).
 *****************************************************************************/
class CafeADVCalculator {
public:
    /**************************************************************************
     * Cache key for CSV data lookup
     **************************************************************************/
    struct CacheKey {
        std::string ric;
        ADVScope    scope;
        
        bool operator==(const CacheKey& other) const {
            return ric == other.ric && scope == other.scope;
        }
    };
    
    struct CacheKeyHash {
        size_t operator()(const CacheKey& k) const {
            return std::hash<std::string>{}(k.ric) ^ 
                   (std::hash<int>{}(static_cast<int>(k.scope)) << 1);
        }
    };
    
    /**************************************************************************
     * Cached ADV entry from CSV
     **************************************************************************/
    struct CachedADVEntry {
        ADVData data;
        Date    date;
        std::optional<double> specialDayMultiplier;
    };

private:
    MessageDeliveryService*                 _mds;
    staticdata::InstrumentStaticSource*     _staticDataSource;
    TimeManager*                            _timeManager;
    std::shared_ptr<db::AsyncDbPool>        _asyncDbPool;
    FLog                                    _flog;
    
    // CSV cache
    std::unordered_map<CacheKey, CachedADVEntry, CacheKeyHash> _csvCache;
    bool _csvMode = false;
    Date _csvDate;  // Date the CSV was generated for
    
    /**************************************************************************
     * Load CSV file into cache
     **************************************************************************/
    bool loadCSV(const std::string& csvPath);
    
    /**************************************************************************
     * Parse a single CSV line using volt::CSVParser
     **************************************************************************/
    std::optional<std::pair<CacheKey, CachedADVEntry>> parseCSVLine(const std::string& line);

public:
    /**************************************************************************
     * CSV mode constructor (with DB fallback)
     * 
     * Loads ADV data from CSV file at construction time.
     * create() calls use O(1) hash lookup, falling back to DB on cache miss.
     * 
     * @param csvPath           Path to CSV file
     * @param mds               Message delivery service
     * @param staticDataSource  Static data source
     * @param timeManager       Time manager
     * @param asyncDbPool       Async database pool (for fallback)
     * @param flog              Logger
     **************************************************************************/
    CafeADVCalculator(
        const std::string& csvPath,
        MessageDeliveryService* mds,
        staticdata::InstrumentStaticSource* staticDataSource,
        TimeManager* timeManager,
        std::shared_ptr<db::AsyncDbPool> asyncDbPool,
        FLog flog);
    
    /**************************************************************************
     * Original DB mode constructor
     * 
     * Each create() call will trigger a DB query.
     * 
     * @param mds               Message delivery service
     * @param staticDataSource  Static data source
     * @param timeManager       Time manager
     * @param asyncDbPool       Async database pool
     * @param flog              Logger
     **************************************************************************/
    CafeADVCalculator(
        MessageDeliveryService* mds,
        staticdata::InstrumentStaticSource* staticDataSource,
        TimeManager* timeManager,
        std::shared_ptr<db::AsyncDbPool> asyncDbPool,
        FLog flog);
    
    /**************************************************************************
     * Create an ADV worker for the given specification
     * 
     * In CSV mode:  O(1) hash lookup, creates CafeADVWorker with initial data
     * In DB mode:   Creates CafeADVWorker that fetches from DB
     * 
     * Both modes create full CafeADVWorker with all update capabilities.
     * 
     * @param specification  ADV specification (instrument, scope, etc.)
     * @param value          Output: the created worker
     **************************************************************************/
    void create(const ADVSpecification& specification, ADVDynamicModel& value);
    
    /**************************************************************************
     * Check if running in CSV mode
     **************************************************************************/
    bool isCSVMode() const { return _csvMode; }
    
    /**************************************************************************
     * Get number of entries in CSV cache
     **************************************************************************/
    size_t cacheSize() const { return _csvCache.size(); }
    
    /**************************************************************************
     * Get the date the CSV was generated for
     **************************************************************************/
    Date csvDate() const { return _csvDate; }
};

} // namespace volt::analysis