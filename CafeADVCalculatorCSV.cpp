/******************************************************************************
 * CafeADVCalculator CSV Support Implementation
 *****************************************************************************/

#include "CafeADVCalculatorCSV.h"
#include "CafeADVWorker.h"
#include "CSVParser.h"

#include <fstream>
#include <algorithm>
#include <cmath>

namespace volt::analysis {

/******************************************************************************
 * Constructor
 *****************************************************************************/
CafeADVCalculator::CafeADVCalculator(
    const std::string& csvPath,
    MessageDeliveryService* mds,
    staticdata::InstrumentStaticSource* staticDataSource,
    TimeManager* timeManager,
    std::shared_ptr<db::AsyncDbPool> asyncDbPool,
    FLog flog)
    : _mds(mds)
    , _staticDataSource(staticDataSource)
    , _timeManager(timeManager)
    , _asyncDbPool(asyncDbPool)
    , _flog(FLog(parent: flog, tag: StringStr() << "CafeADVCalc/"))
{
    if (!csvPath.empty()) {
        FLOG_INFORMATION(_flog, StringStr() << "Loading CSV cache from: " << csvPath);
        
        if (loadCSV(csvPath)) {
            FLOG_INFORMATION(_flog, StringStr() 
                << "CSV cache loaded: " << _csvCache.size() << " entries, date: " << _csvDate);
        } else {
            FLOG_URGENT_ERROR(_flog, StringStr() 
                << "Failed to load CSV file: " << csvPath << " - will use DB for all requests");
        }
    } else {
        FLOG_INFORMATION(_flog, StringStr() << "No CSV path provided, all requests will use DB");
    }
}

/******************************************************************************
 * Load CSV File
 *****************************************************************************/
bool CafeADVCalculator::loadCSV(const std::string& csvPath) {
    std::ifstream file(csvPath);
    if (!file.is_open()) {
        FLOG_URGENT_ERROR(_flog, StringStr() << "Cannot open CSV file: " << csvPath);
        return false;
    }
    
    std::string line;
    
    // Skip header line
    if (!std::getline(file, line)) {
        FLOG_URGENT_ERROR(_flog, StringStr() << "CSV file is empty: " << csvPath);
        return false;
    }
    
    size_t lineNum = 1;
    size_t loaded = 0;
    size_t errors = 0;
    
    while (std::getline(file, line)) {
        ++lineNum;
        
        if (line.empty()) {
            continue;
        }
        
        auto result = parseCSVLine(line);
        if (!result) {
            FLOG_WARNING(_flog, StringStr() << "Failed to parse CSV line " << lineNum << ": " << line);
            ++errors;
            continue;
        }
        
        auto& [key, entry] = *result;
        
        if (loaded == 0) {
            _csvDate = entry.date;
        }
        
        _csvCache[key] = std::move(entry);
        ++loaded;
    }
    
    FLOG_INFORMATION(_flog, StringStr() 
        << "CSV parsing complete: " << loaded << " entries, " << errors << " errors");
    
    return loaded > 0;
}

/******************************************************************************
 * Parse Single CSV Line
 *****************************************************************************/
std::optional<std::pair<CafeADVCalculator::CacheKey, CachedADVEntry>> 
CafeADVCalculator::parseCSVLine(const std::string& line) {
    volt::CSVParser parser;
    parser.parse(line);
    
    if (parser.getCount() < 8) {
        return std::nullopt;
    }
    
    CacheKey key;
    CachedADVEntry entry;
    
    // 0: RIC
    key.ric = parser[0];
    if (key.ric.empty()) {
        return std::nullopt;
    }
    
    // 1: Scope
    std::string scopeStr = parser[1];
    if (scopeStr == "PRIMARY" || scopeStr == "PRIM") {
        key.scope = ADVScope::PRIMARY;
    } else if (scopeStr == "CONS" || scopeStr == "CONSOLIDATED") {
        key.scope = ADVScope::CONS;
    } else {
        return std::nullopt;
    }
    
    // 2: Date
    std::string dateStr = parser[2];
    std::replace(dateStr.begin(), dateStr.end(), '.', '-');
    entry.date = Date::parse(dateStr);
    if (entry.date.isNull()) {
        return std::nullopt;
    }
    
    // 3-7: Volumes
    double dailyVolume = parser.readDouble(3);
    double openingVolume = parser.readDouble(4);
    double closingVolume = parser.readDouble(5);
    double avgTradeSize = parser.readDouble(6);
    double avgContinuousTradeSize = parser.readDouble(7);
    
    // 8: Special day multiplier (optional)
    std::optional<double> specialDayMultiplier;
    if (parser.getCount() > 8) {
        double mult = parser.readDouble(8);
        if (!std::isnan(mult) && mult > 0.0) {
            specialDayMultiplier = mult;
        }
    }
    
    entry.data = ADVData(
        dailyVolume: dailyVolume,
        openingVolume: openingVolume,
        closingVolume: closingVolume,
        intradayAuctionVolume: ADVData::IntradayAuctionVolumeContainer(),
        avgTradeSize: avgTradeSize,
        avgContinuousTradeSize: avgContinuousTradeSize
    );
    
    entry.specialDayMultiplier = specialDayMultiplier;
    
    return std::make_pair(std::move(key), std::move(entry));
}

/******************************************************************************
 * Create ADV Worker
 * 
 * Always checks cache, passes optional to single constructor.
 *****************************************************************************/
void CafeADVCalculator::create(const ADVSpecification& specification, ADVDynamicModel& value) {
    
    // Try to find in cache
    std::optional<CachedADVEntry> cachedData;
    
    auto ricOpt = specification._instrument.get(type: volt::SymbolType::RIC);
    if (ricOpt) {
        CacheKey key{*ricOpt, specification._scope};
        auto it = _csvCache.find(key);
        if (it != _csvCache.end()) {
            cachedData = it->second;
            FLOG_DEBUG(_flog, StringStr() 
                << "Cache hit: " << *ricOpt 
                << " scope=" << (specification._scope == ADVScope::PRIMARY ? "PRIMARY" : "CONS"));
        } else {
            FLOG_DEBUG(_flog, StringStr() 
                << "Cache miss: " << *ricOpt 
                << " scope=" << (specification._scope == ADVScope::PRIMARY ? "PRIMARY" : "CONS"));
        }
    }
    
    // Single constructor - pass optional cached data
    value = new CafeADVWorker(
        specification,
        _mds,
        _staticDataSource,
        _timeManager,
        _asyncDbPool,
        _flog,
        cachedData);
}

} // namespace volt::analysis