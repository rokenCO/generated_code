#pragma once

/******************************************************************************
 * CafeADVCalculator with CSV Cache Support
 * 
 * Loads ADV data from CSV at startup into a cache. On create():
 *   - Cache hit  → CafeADVWorker starts LIVE with pre-loaded data
 *   - Cache miss → CafeADVWorker starts INITIALISING, fetches from DB
 * 
 * Usage:
 *   // With CSV cache
 *   auto calc = CafeADVCalculator(csvPath, mds, staticDataSource, timeManager, asyncDbPool, flog);
 *   
 *   // Without CSV cache (empty cache, all DB queries)
 *   auto calc = CafeADVCalculator("", mds, staticDataSource, timeManager, asyncDbPool, flog);
 * 
 * CSV Format:
 *   ric,scope,date,daily_volume,opening_volume,closing_volume,avg_trade_size,avg_continuous_trade_size,special_day_multiplier
 *   AAPL.O,PRIMARY,2025-01-24,1000000.0,50000.0,75000.0,150.5,145.2,1.0
 * 
 * IMPORTANT: Requires modified CafeADVWorker constructor.
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
 * CachedADVEntry
 * 
 * Holds pre-loaded ADV data from CSV. Passed to CafeADVWorker constructor.
 *****************************************************************************/
struct CachedADVEntry {
    ADVData data;
    Date    date;
    std::optional<double> specialDayMultiplier;
};

/******************************************************************************
 * CafeADVCalculator
 * 
 * Factory class that creates ADV workers.
 * Always checks CSV cache first, passes result to CafeADVWorker constructor.
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

private:
    MessageDeliveryService*                 _mds;
    staticdata::InstrumentStaticSource*     _staticDataSource;
    TimeManager*                            _timeManager;
    std::shared_ptr<db::AsyncDbPool>        _asyncDbPool;
    FLog                                    _flog;
    
    // CSV cache (may be empty if no CSV provided)
    std::unordered_map<CacheKey, CachedADVEntry, CacheKeyHash> _csvCache;
    Date _csvDate;
    
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
     * Constructor
     * 
     * @param csvPath           Path to CSV file (empty string = no cache)
     * @param mds               Message delivery service
     * @param staticDataSource  Static data source
     * @param timeManager       Time manager
     * @param asyncDbPool       Async database pool
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
     * Create an ADV worker for the given specification
     * 
     * Always checks cache first:
     *   - Cache hit  → Worker starts LIVE with cached data
     *   - Cache miss → Worker starts INITIALISING, fetches from DB
     * 
     * @param specification  ADV specification (instrument, scope, etc.)
     * @param value          Output: the created worker
     **************************************************************************/
    void create(const ADVSpecification& specification, ADVDynamicModel& value);
    
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