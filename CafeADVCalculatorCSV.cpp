/******************************************************************************
 * CafeADVCalculator CSV Support Implementation
 *****************************************************************************/

#include "CafeADVCalculatorCSV.h"
#include "CafeADVWorker.h"

#include <fstream>
#include <sstream>
#include <algorithm>

namespace volt::analysis {

/******************************************************************************
 * CSV Mode Constructor
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
    , _flog(FLog(parent: flog, tag: StringStr() << "CafeADVCalc_CSV/"))
    , _csvMode(true)
{
    FLOG_INFORMATION(_flog, StringStr() << "Initializing CafeADVCalculator in CSV mode from: " << csvPath);
    
    if (!loadCSV(csvPath)) {
        FLOG_URGENT_ERROR(_flog, StringStr() << "Failed to load CSV file: " << csvPath 
            << " - all requests will fall back to DB");
    }
    
    FLOG_INFORMATION(_flog, StringStr() 
        << "CafeADVCalculator initialized: " << _csvCache.size() << " entries loaded"
        << ", date: " << _csvDate);
}

/******************************************************************************
 * Original DB Mode Constructor
 *****************************************************************************/
CafeADVCalculator::CafeADVCalculator(
    MessageDeliveryService* mds,
    staticdata::InstrumentStaticSource* staticDataSource,
    TimeManager* timeManager,
    std::shared_ptr<db::AsyncDbPool> asyncDbPool,
    FLog flog)
    : _mds(mds)
    , _staticDataSource(staticDataSource)
    , _timeManager(timeManager)
    , _asyncDbPool(asyncDbPool)
    , _flog(FLog(parent: flog, tag: StringStr() << "CafeADVCalc_DB/"))
    , _csvMode(false)
{
    FLOG_INFORMATION(_flog, StringStr() << "Initializing CafeADVCalculator in DB mode");
}

/******************************************************************************
 * Load CSV File
 * 
 * Expected format (header + data rows):
 * ric,scope,date,daily_volume,opening_volume,closing_volume,avg_trade_size,avg_continuous_trade_size,special_day_multiplier
 * AAPL.O,PRIMARY,2025-01-24,1000000.0,50000.0,75000.0,150.5,145.2,1.0
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
        
        // Skip empty lines
        if (line.empty() || std::all_of(line.begin(), line.end(), ::isspace)) {
            continue;
        }
        
        auto result = parseCSVLine(line);
        if (!result) {
            FLOG_WARNING(_flog, StringStr() << "Failed to parse CSV line " << lineNum << ": " << line);
            ++errors;
            continue;
        }
        
        auto& [key, entry] = *result;
        
        // Store date from first entry
        if (loaded == 0) {
            _csvDate = entry.date;
        }
        
        _csvCache[key] = std::move(entry);
        ++loaded;
    }
    
    FLOG_INFORMATION(_flog, StringStr() 
        << "CSV loading complete: " << loaded << " entries, " << errors << " errors");
    
    return loaded > 0;
}

/******************************************************************************
 * Parse Single CSV Line
 * 
 * Format: ric,scope,date,daily_volume,opening_volume,closing_volume,avg_trade_size,avg_continuous_trade_size,special_day_multiplier
 *****************************************************************************/
std::optional<std::pair<CafeADVCalculator::CacheKey, CafeADVCalculator::CachedADVEntry>> 
CafeADVCalculator::parseCSVLine(const std::string& line) {
    std::istringstream ss(line);
    std::string token;
    
    try {
        CacheKey key;
        CachedADVEntry entry;
        
        // 1. RIC
        if (!std::getline(ss, token, ',')) return std::nullopt;
        key.ric = token;
        
        // 2. Scope (PRIMARY or CONS)
        if (!std::getline(ss, token, ',')) return std::nullopt;
        if (token == "PRIMARY" || token == "PRIM") {
            key.scope = ADVScope::PRIMARY;
        } else if (token == "CONS" || token == "CONSOLIDATED") {
            key.scope = ADVScope::CONS;
        } else {
            return std::nullopt;  // Unknown scope
        }
        
        // 3. Date (YYYY-MM-DD or YYYY.MM.DD)
        if (!std::getline(ss, token, ',')) return std::nullopt;
        // Replace dots with dashes if needed
        std::replace(token.begin(), token.end(), '.', '-');
        entry.date = Date::parse(token);
        if (entry.date.isNull()) {
            return std::nullopt;
        }
        
        // 4. Daily Volume
        if (!std::getline(ss, token, ',')) return std::nullopt;
        double dailyVolume = token.empty() ? NAN : std::stod(token);
        
        // 5. Opening Volume
        if (!std::getline(ss, token, ',')) return std::nullopt;
        double openingVolume = token.empty() ? NAN : std::stod(token);
        
        // 6. Closing Volume
        if (!std::getline(ss, token, ',')) return std::nullopt;
        double closingVolume = token.empty() ? NAN : std::stod(token);
        
        // 7. Average Trade Size
        if (!std::getline(ss, token, ',')) return std::nullopt;
        double avgTradeSize = token.empty() ? NAN : std::stod(token);
        
        // 8. Average Continuous Trade Size
        if (!std::getline(ss, token, ',')) return std::nullopt;
        double avgContinuousTradeSize = token.empty() ? NAN : std::stod(token);
        
        // 9. Special Day Multiplier (optional)
        std::optional<double> specialDayMultiplier;
        if (std::getline(ss, token, ',') && !token.empty()) {
            double mult = std::stod(token);
            if (mult > 0.0) {
                specialDayMultiplier = mult;
            }
        }
        
        // Build ADVData
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
        
    } catch (const std::exception& e) {
        // Parsing error (stod, etc.)
        return std::nullopt;
    }
}

/******************************************************************************
 * Create ADV Worker
 *****************************************************************************/
void CafeADVCalculator::create(const ADVSpecification& specification, ADVDynamicModel& value) {
    
    if (_csvMode) {
        // Try CSV cache first
        auto ricOpt = specification._instrument.get(type: volt::SymbolType::RIC);
        
        if (ricOpt) {
            CacheKey key{*ricOpt, specification._scope};
            auto it = _csvCache.find(key);
            
            if (it != _csvCache.end()) {
                // Cache hit - use CafeADVWorker with initial data
                const CachedADVEntry& entry = it->second;
                
                FLOG_DEBUG(_flog, StringStr() 
                    << "Cache hit: " << *ricOpt 
                    << " scope=" << (specification._scope == ADVScope::PRIMARY ? "PRIMARY" : "CONS"));
                
                // Use the new constructor with pre-loaded data
                value = new CafeADVWorker(
                    specification,
                    _mds,
                    _staticDataSource,
                    _timeManager,
                    _asyncDbPool,
                    _flog,
                    entry.data,                     // Pre-loaded ADV data
                    entry.date,                     // Date from CSV
                    entry.specialDayMultiplier);    // Special day multiplier
                return;
            }
            
            // Cache miss - log and fall through to DB
            FLOG_DEBUG(_flog, StringStr() 
                << "Cache miss, falling back to DB: " << *ricOpt 
                << " scope=" << (specification._scope == ADVScope::PRIMARY ? "PRIMARY" : "CONS"));
        }
        
        // Fall through to DB query
    }
    
    // DB query (original constructor)
    value = new CafeADVWorker(
        specification,
        _mds,
        _staticDataSource,
        _timeManager,
        _asyncDbPool,
        _flog);
}

} // namespace volt::analysis
